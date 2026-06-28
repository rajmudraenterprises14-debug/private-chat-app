import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const PORT = 3000;
const DATA_DIR = path.join(process.cwd(), "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");

// Ensure data directory and files exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJSON(filePath, defaultValue) {
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

function saveJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
  } catch (error) {
    console.error(`Error writing to ${filePath}:`, error);
  }
}

const sessions = {};

function generateSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
}

function getAvatarUrl(username) {
  const seed = encodeURIComponent(username);
  return `https://api.dicebear.com/7.x/adventurer/svg?seed=${seed}`;
}

const app = express();

app.use(express.json());

// CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// ===== AUTH MIDDLEWARE =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Authentication token required" });
  }

  // Check if admin token (starts with "admin-token-")
  if (token.startsWith("admin-token-")) {
    req.isAdmin = true;
    req.userId = "admin";
    return next();
  }

  const session = sessions[token];
  if (!session) {
    return res.status(401).json({ error: "Invalid or expired session token" });
  }

  if (Date.now() > session.expiresAt) {
    delete sessions[token];
    return res.status(401).json({ error: "Session expired" });
  }

  req.userId = session.userId;
  req.isAdmin = false;
  next();
}

// ===== REGULAR USER ENDPOINTS =====

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

  const users = loadJSON(USERS_FILE, []);
  const existingUser = users.find((u) => u.username === trimmedUsername);
  if (existingUser) {
    return res.status(400).json({ error: "Username is already taken" });
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  const userId = crypto.randomUUID();
  const avatarUrl = getAvatarUrl(trimmedUsername);

  const newUser = {
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

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
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
  const users = loadJSON(USERS_FILE, []);
  const user = users.find((u) => u.username === trimmedUsername);

  if (!user) {
    return res.status(400).json({ error: "Invalid username or password" });
  }

  const computedHash = hashPassword(password, user.salt);
  if (computedHash !== user.passwordHash) {
    return res.status(400).json({ error: "Invalid username or password" });
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
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
  if (req.isAdmin) {
    return res.json({ user: { id: "admin", username: "admin", displayName: "Admin" } });
  }
  const currentUserId = req.userId;
  const users = loadJSON(USERS_FILE, []);
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

// Logout
app.post("/api/auth/logout", (req, res) => {
  const { token } = req.body;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.json({ success: true });
});

// Get active users (for frontend)
app.get("/api/auth/active-users", (req, res) => {
  const activeUsers = Object.values(sessions).map(s => {
    const users = loadJSON(USERS_FILE, []);
    const user = users.find(u => u.id === s.userId);
    return user ? user.username : null;
  }).filter(Boolean);
  res.json({ users: activeUsers });
});

// Get other users list (excluding current)
app.get("/api/users", authenticateToken, (req, res) => {
  if (req.isAdmin) {
    // Admin sees all users
    const users = loadJSON(USERS_FILE, []);
    const filteredUsers = users.map((u) => ({
      id: u.id,
      username: u.username,
      displayName: u.displayName,
      avatarUrl: u.avatarUrl,
    }));
    return res.json(filteredUsers);
  }

  const currentUserId = req.userId;
  const users = loadJSON(USERS_FILE, []);
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

// Get private messages
app.get("/api/messages", authenticateToken, (req, res) => {
  const currentUserId = req.isAdmin ? null : req.userId;
  const withUserId = req.query.withUserId;

  if (!withUserId) {
    return res.status(400).json({ error: "withUserId parameter is required" });
  }

  const messages = loadJSON(MESSAGES_FILE, []);

  let filteredMessages;
  if (req.isAdmin) {
    // Admin sees all messages involving this user
    filteredMessages = messages.filter(
      (m) => m.senderId === withUserId || m.receiverId === withUserId
    );
  } else {
    filteredMessages = messages.filter(
      (m) =>
        (m.senderId === currentUserId && m.receiverId === withUserId) ||
        (m.senderId === withUserId && m.receiverId === currentUserId)
    );
  }

  res.json(filteredMessages);
});

// Send a private message
app.post("/api/messages", authenticateToken, (req, res) => {
  if (req.isAdmin) {
    return res.status(403).json({ error: "Admin cannot send messages" });
  }

  const currentUserId = req.userId;
  const { receiverId, ciphertext, iv } = req.body;

  if (!receiverId || !ciphertext || !iv) {
    return res.status(400).json({ error: "receiverId, ciphertext, and iv are required" });
  }

  const users = loadJSON(USERS_FILE, []);
  const receiverExists = users.some((u) => u.id === receiverId);
  if (!receiverExists) {
    return res.status(404).json({ error: "Receiver user not found" });
  }

  const messages = loadJSON(MESSAGES_FILE, []);

  const newMessage = {
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

// Clear private chat history
app.post("/api/messages/clear", authenticateToken, (req, res) => {
  if (req.isAdmin) {
    return res.status(403).json({ error: "Admin cannot clear messages" });
  }

  const currentUserId = req.userId;
  const { withUserId } = req.body;

  if (!withUserId) {
    return res.status(400).json({ error: "withUserId is required" });
  }

  let messages = loadJSON(MESSAGES_FILE, []);
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

// ===== ADMIN ONLY ENDPOINTS =====

// Get all users (admin)
app.get("/api/admin/users", authenticateToken, (req, res) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }

  const users = loadJSON(USERS_FILE, []);
  const messages = loadJSON(MESSAGES_FILE, []);

  // Enrich each user with their message count
  const enrichedUsers = users.map(user => {
    const userMessages = messages.filter(
      m => m.senderId === user.id || m.receiverId === user.id
    );
    return {
      ...user,
      messageCount: userMessages.length,
      // Remove sensitive data for safety (but admin needs them for password reset)
      // We'll keep passwordHash and salt only for admin use
    };
  });

  res.json({ users: enrichedUsers });
});

// Delete a user (admin)
app.delete("/api/admin/users/:userId", authenticateToken, (req, res) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }

  const userId = req.params.userId;
  let users = loadJSON(USERS_FILE, []);

  const userIndex = users.findIndex(u => u.id === userId);
  if (userIndex === -1) {
    return res.status(404).json({ error: "User not found" });
  }

  // Prevent deleting admin user (if admin is in users list)
  if (users[userIndex].username === "admin") {
    return res.status(403).json({ error: "Cannot delete admin user" });
  }

  // Remove user
  const deletedUser = users.splice(userIndex, 1)[0];
  saveJSON(USERS_FILE, users);

  // Delete all messages involving this user
  let messages = loadJSON(MESSAGES_FILE, []);
  messages = messages.filter(
    m => m.senderId !== userId && m.receiverId !== userId
  );
  saveJSON(MESSAGES_FILE, messages);

  // Remove any active sessions for this user
  for (const [token, session] of Object.entries(sessions)) {
    if (session.userId === userId) {
      delete sessions[token];
    }
  }

  res.json({
    success: true,
    message: `User ${deletedUser.username} deleted along with ${messages.length} messages`
  });
});

// Admin reset password
app.post("/api/admin/reset-password", authenticateToken, (req, res) => {
  if (!req.isAdmin) {
    return res.status(403).json({ error: "Admin access required" });
  }

  const { userId, newPassword } = req.body;

  if (!userId || !newPassword) {
    return res.status(400).json({ error: "userId and newPassword are required" });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: "Password must be at least 4 characters" });
  }

  let users = loadJSON(USERS_FILE, []);
  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  if (user.username === "admin") {
    return res.status(403).json({ error: "Cannot reset admin password" });
  }

  // Update password
  const newSalt = generateSalt();
  const newHash = hashPassword(newPassword, newSalt);
  user.passwordHash = newHash;
  user.salt = newSalt;
  saveJSON(USERS_FILE, users);

  // Remove any active sessions for this user
  for (const [token, session] of Object.entries(sessions)) {
    if (session.userId === userId) {
      delete sessions[token];
    }
  }

  res.json({
    success: true,
    message: `Password reset for ${user.username}`
  });
});

// User self reset password (forgot password)
app.post("/api/auth/reset-password", async (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).json({ error: "Username and new password are required" });
  }

  if (newPassword.length < 4) {
    return res.status(400).json({ error: "Password must be at least 4 characters" });
  }

  const trimmedUsername = username.trim().toLowerCase();
  let users = loadJSON(USERS_FILE, []);
  const user = users.find(u => u.username === trimmedUsername);
  if (!user) {
    return res.status(404).json({ error: "Username not found" });
  }

  // Update password
  const newSalt = generateSalt();
  const newHash = hashPassword(newPassword, newSalt);
  user.passwordHash = newHash;
  user.salt = newSalt;
  saveJSON(USERS_FILE, users);

  // Remove any active sessions for this user
  for (const [token, session] of Object.entries(sessions)) {
    if (session.userId === user.id) {
      delete sessions[token];
    }
  }

  res.json({
    success: true,
    message: `Password reset successfully for ${user.username}`
  });
});

// ===== SERVE FRONTEND =====
app.use(express.static(process.cwd()));
app.get("*", (req, res) => {
  res.sendFile(path.join(process.cwd(), "index.html"));
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Chat App Server] running on http://localhost:${PORT}`);
});