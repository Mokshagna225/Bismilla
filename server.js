import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import Database from "better-sqlite3";
import crypto from "crypto";
import admin from "firebase-admin";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";


const app = express();
const PORT = 5000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const clientPath = path.join(__dirname, "../client");

// Firebase Admin is used only on the server to verify Firebase ID tokens.
// Set GOOGLE_APPLICATION_CREDENTIALS to your Firebase service-account JSON file
// before starting the server.
let firebaseAdminReady = false;
try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    admin.initializeApp({
      credential: admin.credential.applicationDefault()
    });
    firebaseAdminReady = true;
    console.log("Firebase Admin authentication enabled.");
  } else {
    console.warn("Firebase Admin is not configured. Set GOOGLE_APPLICATION_CREDENTIALS.");
  }
} catch (err) {
  console.error("Firebase Admin initialization failed:", err.message);
}

app.use(cors({ origin: true }));
app.use(express.json());
app.use(express.static(clientPath));

app.get("/", (req, res) => {
  res.sendFile(path.join(clientPath, "bismilla_biryani_app.html"));
});

const db = new Database("bismilla.db");
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firebase_uid TEXT UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  mobile TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  address TEXT DEFAULT '',
  latitude REAL,
  longitude REAL,
  location_accuracy REAL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  login_time TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  target TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  verified INTEGER NOT NULL DEFAULT 0,
  verification_token_hash TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  order_id TEXT NOT NULL UNIQUE,
  amount REAL NOT NULL,
  payment_method TEXT NOT NULL,
  payment_status TEXT NOT NULL,
  order_status TEXT NOT NULL,
  items_json TEXT NOT NULL,
  address TEXT,
  payment_time TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_login_user_time ON login_events(user_id, login_time);
CREATE INDEX IF NOT EXISTS idx_payment_user_time ON payments(user_id, payment_time);
`);

// Migrate databases created by older versions so GPS coordinates can be stored.
const userColumns = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userColumns.includes("firebase_uid")) db.exec("ALTER TABLE users ADD COLUMN firebase_uid TEXT");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid) WHERE firebase_uid IS NOT NULL");
if (!userColumns.includes("latitude")) db.exec("ALTER TABLE users ADD COLUMN latitude REAL");
if (!userColumns.includes("longitude")) db.exec("ALTER TABLE users ADD COLUMN longitude REAL");
if (!userColumns.includes("location_accuracy")) db.exec("ALTER TABLE users ADD COLUMN location_accuracy REAL");

const paymentColumns = db.prepare("PRAGMA table_info(payments)").all().map(c => c.name);
if (!paymentColumns.includes("latitude")) db.exec("ALTER TABLE payments ADD COLUMN latitude REAL");
if (!paymentColumns.includes("longitude")) db.exec("ALTER TABLE payments ADD COLUMN longitude REAL");
if (!paymentColumns.includes("location_accuracy")) db.exec("ALTER TABLE payments ADD COLUMN location_accuracy REAL");

function nowIso() {
  return new Date().toISOString();
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashOtp(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function randomOtp() {
  return String(crypto.randomInt(100000, 1000000));
}

const mailer = (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD)
  ? nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
    })
  : null;

async function sendEmailOtp(email, otp, purpose) {
  if (!mailer) throw new Error("Gmail SMTP is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD.");
  const subject = purpose === "registration" ? "Bismilla Biryani - Email Verification OTP" : "Bismilla Biryani - Password Reset OTP";
  await mailer.sendMail({
    from: `Bismilla Biryani <${process.env.GMAIL_USER}>`,
    to: email,
    subject,
    text: `Your Bismilla Biryani OTP is ${otp}. It expires in 10 minutes. Do not share this OTP with anyone.`
  });
}

function publicUser(row) {
  return {
    id: row.id,
    uid: row.firebase_uid || `user_${row.id}`,
    email: row.email,
    profile: {
      name: row.name,
      email: row.email,
      mobile: row.mobile,
      address: row.address || "",
      latitude: row.latitude ?? null,
      longitude: row.longitude ?? null,
      accuracy: row.location_accuracy ?? null,
      createdAt: row.created_at
    }
  };
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  if (!token) {
    return res.status(401).json({ message: "Please login first." });
  }

  const session = db.prepare(`
    SELECT s.*, u.*
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ? AND s.expires_at > ?
  `).get(token, nowIso());

  if (!session) {
    return res.status(401).json({ message: "Session expired. Please login again." });
  }

  req.token = token;
  req.user = session;
  next();
}

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Bismilla Biryani Database API",
    database: "SQLite"
  });
});


// ---------------- OTP AUTHENTICATION ----------------
app.post("/api/auth/email-otp/send", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const purpose = String(req.body.purpose || "");
    if (!/^\S+@\S+\.\S+$/.test(email) || !["registration", "password-reset"].includes(purpose)) {
      return res.status(400).json({ message: "Valid email and OTP purpose are required." });
    }

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (purpose === "registration" && existing) return res.status(409).json({ message: "Email already registered. Please login." });
    if (purpose === "password-reset" && !existing) return res.status(404).json({ message: "No account found for this email." });

    const challengeId = crypto.randomBytes(24).toString("hex");
    const otp = randomOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    db.prepare(`INSERT INTO otp_challenges (id,purpose,target,otp_hash,expires_at,created_at) VALUES (?,?,?,?,?,?)`)
      .run(challengeId, purpose, email, hashOtp(otp), expiresAt, nowIso());

    await sendEmailOtp(email, otp, purpose);
    res.json({ success: true, challengeId, expiresInSeconds: 600 });
  } catch (err) {
    console.error("Email OTP send failed:", err);
    res.status(500).json({ message: err.message || "Could not send email OTP." });
  }
});

app.post("/api/auth/email-otp/verify", (req, res) => {
  try {
    const { challengeId, email, otp, purpose } = req.body || {};
    const challenge = db.prepare("SELECT * FROM otp_challenges WHERE id = ? AND purpose = ? AND target = ?")
      .get(challengeId, purpose, String(email || "").trim().toLowerCase());
    if (!challenge) return res.status(400).json({ message: "Invalid or expired OTP request." });
    if (challenge.verified) return res.status(400).json({ message: "OTP has already been used." });
    if (new Date(challenge.expires_at).getTime() < Date.now()) return res.status(400).json({ message: "OTP expired. Please request a new OTP." });
    if (challenge.attempts >= 5) return res.status(429).json({ message: "Too many incorrect OTP attempts." });

    if (hashOtp(otp || "") !== challenge.otp_hash) {
      db.prepare("UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?").run(challenge.id);
      return res.status(400).json({ message: "Incorrect OTP." });
    }

    const verificationToken = crypto.randomBytes(32).toString("hex");
    db.prepare("UPDATE otp_challenges SET verified = 1, verification_token_hash = ? WHERE id = ?")
      .run(hashOtp(verificationToken), challenge.id);
    res.json({ success: true, verificationToken });
  } catch (err) {
    console.error("Email OTP verify failed:", err);
    res.status(500).json({ message: "Could not verify email OTP." });
  }
});

app.post("/api/auth/resolve-login", (req, res) => {
  const mobile = String(req.body.mobile || "").replace(/\D/g, "");
  if (mobile.length !== 10) return res.status(400).json({ message: "Invalid mobile number." });
  const user = db.prepare("SELECT email FROM users WHERE mobile = ?").get(mobile);
  if (!user) return res.status(401).json({ message: "Invalid mobile or password." });
  res.json({ email: user.email });
});

app.post("/api/auth/password-reset", async (req, res) => {
  try {
    const { method, verificationToken, idToken, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 6) return res.status(400).json({ message: "Password must contain at least 6 characters." });
    if (!firebaseAdminReady) return res.status(503).json({ message: "Firebase Admin is not configured." });

    let uid;
    if (method === "email") {
      const tokenHash = hashOtp(verificationToken || "");
      const challenge = db.prepare(`SELECT * FROM otp_challenges WHERE verification_token_hash = ? AND purpose = 'password-reset' AND verified = 1`).get(tokenHash);
      if (!challenge || new Date(challenge.expires_at).getTime() < Date.now()) return res.status(400).json({ message: "Password reset verification expired. Request a new OTP." });
      const user = db.prepare("SELECT firebase_uid FROM users WHERE email = ?").get(challenge.target);
      if (!user?.firebase_uid) return res.status(404).json({ message: "Firebase account not found." });
      uid = user.firebase_uid;
      db.prepare("DELETE FROM otp_challenges WHERE id = ?").run(challenge.id);
    } else if (method === "mobile") {
      if (!idToken) return res.status(400).json({ message: "Verified Firebase mobile token is required." });
      const decoded = await admin.auth().verifyIdToken(idToken);
      if (!decoded.phone_number) return res.status(400).json({ message: "Mobile number was not verified." });
      uid = decoded.uid;
    } else {
      return res.status(400).json({ message: "Invalid password reset method." });
    }

    await admin.auth().updateUser(uid, { password: newPassword });
    if (method === "mobile") await admin.auth().revokeRefreshTokens(uid);
    res.json({ success: true, message: "Password updated successfully." });
  } catch (err) {
    console.error("Password reset failed:", err);
    res.status(400).json({ message: err.message || "Password reset failed." });
  }
});

// Exchange a Firebase ID token for the app's existing SQLite session token.
// Firebase handles the password. SQLite continues to store application/profile,
// login-history, location and order data.
app.post("/api/auth/firebase", async (req, res) => {
  try {
    if (!firebaseAdminReady) {
      return res.status(503).json({
        message: "Firebase Admin is not configured on the server. Set GOOGLE_APPLICATION_CREDENTIALS."
      });
    }

    let { idToken, name = "", mobile = "", mode = "login" } = req.body;
    if (!idToken) return res.status(400).json({ message: "Firebase ID token is required." });

    const decoded = await admin.auth().verifyIdToken(idToken);
    const firebaseUid = decoded.uid;
    const email = (decoded.email || "").trim().toLowerCase();

    if (!email) return res.status(400).json({ message: "Firebase account has no email address." });

    if (mobile) {
      const normalizedMobile = String(mobile).replace(/\D/g, "");
      const mobileOwner = db.prepare("SELECT id, firebase_uid FROM users WHERE mobile = ?").get(normalizedMobile);
      if (mobileOwner && mobileOwner.firebase_uid && mobileOwner.firebase_uid !== firebaseUid) {
        return res.status(409).json({ message: "Mobile number is already registered." });
      }
      mobile = normalizedMobile;
    }

    let user = db.prepare("SELECT * FROM users WHERE firebase_uid = ?").get(firebaseUid);

    if (!user) {
      user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

      if (user) {
        db.prepare("UPDATE users SET firebase_uid = ? WHERE id = ?").run(firebaseUid, user.id);
        user = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
      } else {
        const result = db.prepare(`
          INSERT INTO users (firebase_uid, name, email, mobile, password_hash, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          firebaseUid,
          name || decoded.name || email.split("@")[0],
          email,
          mobile || "",
          "",
          nowIso()
        );
        user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
      }
    } else if (name || mobile) {
      db.prepare(`
        UPDATE users
        SET name = COALESCE(NULLIF(?, ''), name),
            mobile = COALESCE(NULLIF(?, ''), mobile)
        WHERE id = ?
      `).run(name, mobile, user.id);
      user = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    }

    const loginTime = nowIso();
    if (mode !== "register") {
      db.prepare(`
        INSERT INTO login_events (user_id, login_time)
        VALUES (?, ?)
      `).run(user.id, loginTime);
    }

    const token = createToken();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO sessions (token, user_id, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(token, user.id, loginTime, expires);

    res.status(mode === "register" ? 201 : 200).json({
      token,
      user: publicUser(user),
      loginTime: mode === "register" ? null : loginTime
    });
  } catch (err) {
    console.error("Firebase auth sync failed:", err);
    res.status(401).json({ message: "Firebase authentication failed." });
  }
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, mobile, password } = req.body;

    if (!name || !email || !mobile || !password) {
      return res.status(400).json({ message: "Name, email, mobile and password are required." });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must contain at least 6 characters." });
    }

    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) {
      return res.status(409).json({ message: "Email already registered. Please login." });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(`
      INSERT INTO users (name, email, mobile, password_hash, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(name, email, mobile, passwordHash, nowIso());

    const userRow = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);

    // Registration is not counted as a login event.
    const token = createToken();
    const created = nowIso();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO sessions (token, user_id, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(token, userRow.id, created, expires);

    res.status(201).json({
      token,
      user: publicUser(userRow),
      loginTime: null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email || "");
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const valid = await bcrypt.compare(password || "", user.password_hash);
    if (!valid) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const loginTime = nowIso();

    // Every successful login gets its own database record.
    db.prepare(`
      INSERT INTO login_events (user_id, login_time)
      VALUES (?, ?)
    `).run(user.id, loginTime);

    const token = createToken();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO sessions (token, user_id, created_at, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(token, user.id, loginTime, expires);

    res.json({
      token,
      user: publicUser(user),
      loginTime
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Login failed." });
  }
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/api/auth/logout", auth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(req.token);
  res.json({ success: true });
});

app.put("/api/users/profile", auth, (req, res) => {
  const { name, mobile, address, latitude, longitude, accuracy } = req.body;

  const nextName = name ?? req.user.name;
  const nextMobile = mobile ?? req.user.mobile;
  const nextAddress = address ?? req.user.address ?? "";

  const nextLatitude = latitude !== null && latitude !== undefined ? Number(latitude) : req.user.latitude ?? null;
  const nextLongitude = longitude !== null && longitude !== undefined ? Number(longitude) : req.user.longitude ?? null;
  const nextAccuracy = accuracy !== null && accuracy !== undefined ? Number(accuracy) : req.user.location_accuracy ?? null;

  if (
    (latitude !== null && latitude !== undefined && !Number.isFinite(nextLatitude)) ||
    (longitude !== null && longitude !== undefined && !Number.isFinite(nextLongitude))
  ) {
    return res.status(400).json({ message: "Invalid GPS coordinates." });
  }

  db.prepare(`
    UPDATE users
    SET name = ?, mobile = ?, address = ?, latitude = ?, longitude = ?, location_accuracy = ?
    WHERE id = ?
  `).run(nextName, nextMobile, nextAddress, nextLatitude, nextLongitude, nextAccuracy, req.user.id);

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  res.json({ profile: publicUser(user).profile });
});

app.post("/api/payments", auth, (req, res) => {
  try {
    const { items, totals, paymentMethod, address, latitude, longitude, accuracy } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "No items in the order." });
    }

    const amount = Number(totals?.total);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ message: "Invalid payment amount." });
    }

    const paymentTime = nowIso();
    const orderId = `BIM-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

    db.prepare(`
      INSERT INTO payments
      (user_id, order_id, amount, payment_method, payment_status, order_status, items_json, address, latitude, longitude, location_accuracy, payment_time)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      orderId,
      amount,
      paymentMethod || "UPI QR",
      "Payment Claimed",
      "Pending Confirmation",
      JSON.stringify(items),
      address || req.user.address || "",
      latitude !== null && latitude !== undefined ? Number(latitude) : req.user.latitude ?? null,
      longitude !== null && longitude !== undefined ? Number(longitude) : req.user.longitude ?? null,
      accuracy !== null && accuracy !== undefined ? Number(accuracy) : req.user.location_accuracy ?? null,
      paymentTime
    );

    res.status(201).json({
      success: true,
      orderId,
      paymentTime
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Payment could not be recorded." });
  }
});

// Admin/report endpoint for development.
// In production, protect this with a real admin role and authentication.
app.get("/api/admin/activity", (req, res) => {
  const users = db.prepare(`
    SELECT id, name, email, mobile, address, latitude, longitude, location_accuracy, created_at
    FROM users
    ORDER BY created_at DESC
  `).all();

  const logins = db.prepare(`
    SELECT l.id, l.user_id, u.email, l.login_time
    FROM login_events l
    JOIN users u ON u.id = l.user_id
    ORDER BY l.login_time DESC
  `).all();

  const payments = db.prepare(`
    SELECT p.id, p.order_id, p.user_id, u.name, u.email,
           p.amount, p.payment_method, p.payment_status,
           p.order_status, p.items_json, p.address, p.latitude,
           p.longitude, p.location_accuracy, p.payment_time
    FROM payments p
    JOIN users u ON u.id = p.user_id
    ORDER BY p.payment_time DESC
  `).all();

  res.json({ users, logins, payments });
});

app.listen(PORT, () => {
    console.log(`Bismilla database server running at http://localhost:${PORT}`);
});
