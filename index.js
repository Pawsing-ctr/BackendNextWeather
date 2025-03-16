const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  revokedRefreshToken,
} = require("./JWT-service");
const {
  authorizeRoles,
  checkRole,
  authenticateToken,
} = require("./auth-middleware");

const user = process.env.USER;
const database = process.env.DATABASE;
const password = process.env.PASSWORD;

const app = express();
const PORT = 3011;

app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3011"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Set-Cookie"],
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  user,
  host: "localhost",
  database,
  password,
  port: 5432,
});

// -------- функцию для регистрации --------
app.post("/api/users/register", async (req, res) => {
  const { email, password, day, month, year, role = "user" } = req.body;

  const validRole = role === "admin" ? "admin" : "user";

  try {
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        message: "User with this email already exists",
      });
    }

    const passwordHash = await bcrypt.hash(password, 7);

    const result = await pool.query(
      "INSERT INTO users (email, password, day, month, year, role) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, email, day, month, year, role",
      [email, passwordHash, day, month, year, validRole]
    );

    const user = result.rows[0];

    const accessToken = generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user.id);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: parseInt(process.env.REFRESH_TOKEN_COOKIE_MAX_AGE),
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRY),
    });

    res.status(201).json({
      message: "User registered successfully",
      accessToken,
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// --------- фукнция для логина ------------
app.post("/api/users/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, email, password, role FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = await generateRefreshToken(user.id);

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRY),
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: parseInt(process.env.REFRESH_TOKEN_COOKIE_MAX_AGE),
    });

    res.status(200).json({
      success: true,
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error login", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------- функция обновления токена --------------
app.post("/api/users/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  try {
    const user = await verifyRefreshToken(refreshToken);

    if (!user) {
      res.clearCookie("refreshToken");
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    await revokedRefreshToken(refreshToken);

    const accessToken = generateAccessToken(user);
    const newRefreshToken = await generateRefreshToken(user.id);

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: parseInt(process.env.REFRESH_TOKEN_COOKIE_MAX_AGE),
    });

    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: parseInt(process.env.ACCESS_TOKEN_EXPIRY),
    });

    res.status(200).json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error refreshing token:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// --------------- функция выхода пользователя -----------
app.post("/api/users/logout", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    try {
      await revokedRefreshToken(refreshToken);
    } catch (error) {
      console.error("Error during logout:", error);
    }
  }

  res.clearCookie("refreshToken");
  res.clearCookie("accessToken");

  res.status(200).json({ message: "Logged out successfully" });
});

// Маршрутизация для админ страницы
app.get(
  "/api/users/admin",
  authenticateToken,
  authorizeRoles("admin"),
  async (req, res) => {
    try {
      const result = await pool.query("SELECT id, email, role FROM users");

      res.status(200).json(result.rows);
    } catch (error) {
      console.error("Error get users", error);
      res.status(500).json({ message: "Server error", error: error.message });
    }
  }
);

// Проверка текущего пользователя
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [req.user.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = result.rows[0];

    res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error get user", error);
    res.status(500).json({ message: "Server error:", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
