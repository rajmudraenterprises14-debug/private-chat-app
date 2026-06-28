import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { createServer as createViteServer } from "vite";

// Interfaces
interface User {
  id: string;
  username: string;
  passwordHash: string;
  salt: string;
  displayName: string;
  avatarUrl: string;
  createdAt: string;
}

interface Message {
  id: string;
  senderId: string;
  receiverId: string;
  ciphertext: string; // Base64 encrypted text
  iv: string; // Hex initialization vector
  timestamp: number;
}

interface Session {
  token: string;
  userId: string;
  expiresAt: number;
}

const PORT = 3000;
const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");

// Ensure data directory and files exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJSON<T>(filePath: string, defaultValue: T): T {
  try {
    if (fs.existsSync(filePath)) {
      const content = fs.readFileSync(filePath, "utf-8");
      return JSON.parse(content);
    }
  } catch (error) {
    console.error(`Error reading ${filePath}:`, error);
  }
  return defaultValue;
}

function saveJSON<T>(filePath: string, data: T): void {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
  } catch (error) {
    console.error(`Error writing to ${filePath}:`, error);
  }
}

// In-memory sessions (could be persistent, but memory is perfect for session life-cycles)
const sessions: Record<string, Session> = {};

// Helper for secure password hashing
function generateSalt(): string {
  return crypto.randomBytes(16).toString("hex");
}

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

// Generate pre-configured avatar URLs based on initials or random dicebear style
function getAvatarUrl(username: string): string {
  const seed = encodeURIComponent(username);
  return `https://api.dicebear.com/7.x/adventurer/svg?seed=${seed}`;
}

async function startServer() {
  const app = express();

  // Middleware to parse incoming JSON bodies
  app.use(express.json());

  // CORS headers just in case
  app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    if (req.method === "OPTIONS") {
      return res.sendStatus(200);
    }
    next();
  });

  // Authentication Middleware
  function authenticateToken(req: express.Request, res: express.Response, next: express.NextFunction) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Authentication token required" });
    }

    const session = sessions[token];
    if (!session) {
      return res.status(401).json({ error: "Invalid or expired session token" });
    }

    if (Date.now() > session.expiresAt) {
      delete sessions[token];
      return res.status(401).json({ error: "Session expired" });
    }

    // Attach user information to request
    (req as any).userId = session.userId;
    next();
  }

  // --- API Routes ---

  // Register User
  app.post("/api/auth/register", (req, res) => {
    const { username, password, displayName } = req.body;

    if (!username || !password || !displayName) {
      return res.status(400).json({ error: "Username, password, and display name are required" });
    }

    const trimmedUsername = username.trim().toLowerCase();
    if (trimmedUsername.length < 3 || trimmedUsername.length > 20) {
      return res.status(400).json({ error: "Username must be between 3 and 20 characters" });
    }

    if (!/^[a-zA-Z0-9_]+$/.test(trimmedUsername)) {
      return res.status(400).json({ error: "Username can only contain letters, numbers, and underscores" });
    }

    const users = loadJSON<User[]>(USERS_FILE, []);
    const existingUser = users.find((u) => u.username === trimmedUsername);
    if (existingUser) {
      return res.status(400).json({ error: "Username is already taken" });
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);
    const userId = crypto.randomUUID();
    const avatarUrl = getAvatarUrl(trimmedUsername);

    const newUser: User = {
      id: userId,
      username: trimmedUsername,
      passwordHash,
      salt,
      displayName: displayName.trim(),
      avatarUrl,
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    saveJSON(USERS_FILE, users);

    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    sessions[token] = { token, userId, expiresAt };

    res.status(201).json({
      token,
      user: {
        id: userId,
        username: trimmedUsername,
        displayName: newUser.displayName,
        avatarUrl,
      },
    });
  });

  // Login User
  app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required" });
    }

    const trimmedUsername = username.trim().toLowerCase();
    const users = loadJSON<User[]>(USERS_FILE, []);
    const user = users.find((u) => u.username === trimmedUsername);

    if (!user) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const computedHash = hashPassword(password, user.salt);
    if (computedHash !== user.passwordHash) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    sessions[token] = { token, userId: user.id, expiresAt };

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
      },
    });
  });

  // Get current session user
  app.get("/api/auth/me", authenticateToken, (req, res) => {
    const currentUserId = (req as any).userId;
    const users = loadJSON<User[]>(USERS_FILE, []);
    const user = users.find((u) => u.id === currentUserId);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      user: {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
      },
    });
  });

  // Get other users list (excluding current logged-in user)
  app.get("/api/users", authenticateToken, (req, res) => {
    const currentUserId = (req as any).userId;
    const users = loadJSON<User[]>(USERS_FILE, []);
    
    // Map to safe public user profile, excluding passwords/salts
    const filteredUsers = users
      .filter((u) => u.id !== currentUserId)
      .map((u) => ({
        id: u.id,
        username: u.username,
        displayName: u.displayName,
        avatarUrl: u.avatarUrl,
      }));

    res.json(filteredUsers);
  });

  // Get private messages between current user and specified user
  app.get("/api/messages", authenticateToken, (req, res) => {
    const currentUserId = (req as any).userId;
    const withUserId = req.query.withUserId as string;

    if (!withUserId) {
      return res.status(400).json({ error: "withUserId parameter is required" });
    }

    const messages = loadJSON<Message[]>(MESSAGES_FILE, []);

    // Secure check: Only fetch messages exchanged between current user and requested user
    const filteredMessages = messages.filter(
      (m) =>
        (m.senderId === currentUserId && m.receiverId === withUserId) ||
        (m.senderId === withUserId && m.receiverId === currentUserId)
    );

    res.json(filteredMessages);
  });

  // Send a private message (E2EE encrypted by the client)
  app.post("/api/messages", authenticateToken, (req, res) => {
    const currentUserId = (req as any).userId;
    const { receiverId, ciphertext, iv } = req.body;

    if (!receiverId || !ciphertext || !iv) {
      return res.status(400).json({ error: "receiverId, ciphertext, and iv are required" });
    }

    // Verify receiver exists
    const users = loadJSON<User[]>(USERS_FILE, []);
    const receiverExists = users.some((u) => u.id === receiverId);
    if (!receiverExists) {
      return res.status(404).json({ error: "Receiver user not found" });
    }

    const messages = loadJSON<Message[]>(MESSAGES_FILE, []);

    const newMessage: Message = {
      id: crypto.randomUUID(),
      senderId: currentUserId,
      receiverId,
      ciphertext,
      iv,
      timestamp: Date.now(),
    };

    messages.push(newMessage);
    saveJSON(MESSAGES_FILE, messages);

    res.status(201).json(newMessage);
  });

  // Clear private chat history between current user and target user
  app.post("/api/messages/clear", authenticateToken, (req, res) => {
    const currentUserId = (req as any).userId;
    const { withUserId } = req.body;

    if (!withUserId) {
      return res.status(400).json({ error: "withUserId is required" });
    }

    let messages = loadJSON<Message[]>(MESSAGES_FILE, []);

    // Filter out messages between these two users
    const originalCount = messages.length;
    messages = messages.filter(
      (m) =>
        !(
          (m.senderId === currentUserId && m.receiverId === withUserId) ||
          (m.senderId === withUserId && m.receiverId === currentUserId)
        )
    );

    saveJSON(MESSAGES_FILE, messages);

    res.json({
      success: true,
      clearedCount: originalCount - messages.length,
    });
  });

  // --- Serve Frontend App ---

  const distPath = path.join(process.cwd(), "dist");
  const hasDist = fs.existsSync(path.join(distPath, "index.html"));

  if (hasDist) {
    // Serve built static files from dist folder
    console.log("[Chat App Server] Serving static files from dist/ folder (Production mode).");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  } else {
    // In development mode, mount Vite middleware to serve assets with HMR & TS support
    console.log("[Chat App Server] Starting in Development mode using Vite dev server.");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  }

  // Start Server listening on 0.0.0.0:3000
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[Chat App Server] running securely on http://localhost:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Failed to start full-stack chat server:", error);
});