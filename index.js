const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  revokedRefreshToken,
} = require("./JWT-service");
const { authorizeRoles, authenticateToken } = require("./auth-middleware");
const multer = require("multer");

const user = process.env.USER;
const database = process.env.DATABASE;
const password = process.env.PASSWORD;
const host = process.env.HOST;
const port = process.env.PORT;

const app = express();
const PORT = 5000;

app.use(
  cors({
    origin: ["https://backendnextweather-production.up.railway.app"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["Set-Cookie"],
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const upload = multer({ storage: multer.memoryStorage() });

const pool = new Pool({
  user,
  host,
  database,
  password,
  port,
  ssl: {
    rejectUnauthorized: false,
  },
});

// -------- эндпоинт для регистрации --------
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
        year: user.year,
      },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// --------- эндпоинт для логина ------------
app.post("/api/users/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, email, password, role, year FROM users WHERE email = $1",
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
        year: user.year,
      },
    });
  } catch (error) {
    console.error("Error login", error);
    res.status(500).json({ message: "Server Error" });
  }
});

// -------------- эндпоинт обновления токена --------------
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
        year: user.year,
      },
    });
  } catch (error) {
    console.error("Error refreshing token:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// --------------- эндпоинт выхода пользователя -----------
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
  res.clearCookie("userBirthYear");

  res.status(200).json({ message: "Logged out successfully" });
});

// ------ энпоинт для добавления пользователя в админа -----
app.patch("/api/users/make-admin", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const user = result.rows[0];

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Неверный пароль" });
    }

    if (user.role === "admin") {
      return res
        .status(400)
        .json({ message: "Пользователь уже является админом" });
    }

    await pool.query("UPDATE users SET role = 'admin' WHERE email = $1", [
      email,
    ]);

    res.status(200).json({ message: "Пользователь теперь админ" });
  } catch (error) {
    console.error("Ошибка при выдаче прав администратора:", error);
    res.status(500).json({ message: "Ошибка сервера", error: error.message });
  }
});

// Проверка текущего пользователя
app.get("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, role, year FROM users WHERE id = $1",
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
        year: user.year,
      },
    });
  } catch (error) {
    console.error("Error get user", error);
    res.status(500).json({ message: "Server error:", error: error.message });
  }
});

app.put("/api/users/update", authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { email, newPassword } = req.body;

  try {
    let passwordHash;

    if (newPassword) {
      const result = await pool.query(
        "SELECT password FROM users WHERE id = $1",
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ message: "Пользователь не найдет" });
      }

      const currentHashedPassword = result.rows[0].password;

      const isSamePassword = await bcrypt.compare(
        newPassword,
        currentHashedPassword
      );

      if (isSamePassword) {
        return res
          .status(400)
          .json({ message: "Новый пароль не должен совпадать со старым" });
      }

      passwordHash = await bcrypt.hash(newPassword, 7);
    }

    const updateQuery = `
      UPDATE users SET
        email = COALESCE($1, email),
        password = COALESCE($2, password)
      WHERE id = $3
      RETURNING id, email
    `;

    const result = await pool.query(updateQuery, [
      email || null,
      passwordHash || null,
      userId,
    ]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    if (passwordHash) {
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");
      res.clearCookie("userBirthYear");
      return res
        .status(200)
        .json({ message: "Пароль обновлён. Войдите заново." });
    }

    res.status(200).json({
      message: "User data updated successfully",
      user: result.rows[0],
    });
  } catch (error) {
    console.error("Error updating user data:", error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

// Получить все новости
app.get("/api/news", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, title, description, created_at FROM news"
    );
    const newsWithImages = await Promise.all(
      result.rows.map(async (item) => {
        const imageResult = await pool.query(
          "SELECT image FROM news WHERE id = $1",
          [item.id]
        );
        const image = imageResult.rows[0]?.image;
        return {
          ...item,
          imageUrl: image
            ? `data:image/jpeg;base64,${Buffer.from(image).toString("base64")}`
            : null,
        };
      })
    );
    res.json(newsWithImages);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Ошибка при получении данных новостей" });
  }
});

//Получить (определенную) новость по id
app.get("/news/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("SELECT * FROM news WHERE id = $1", [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Новость не найдена" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Ошибка при получении данных" });
  }
});

//Добавить новость
app.post("/api/news", upload.single("image"), async (req, res) => {
  const { title, description } = req.body;
  const imageBuffer = req.file ? req.file.buffer : null;

  try {
    const result = await pool.query(
      "INSERT INTO news (title, description, image) VALUES ($1,$2,$3) RETURNING *",
      [title, description, imageBuffer]
    );
    res.status(201).json({
      message: "Новость создана",
      news: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Ошибка при добавлении новости" });
  }
});

// Удалить новость
app.delete("/api/news/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      "DELETE FROM news WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Новость не найдена" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Ошибка при удалении новости" });
  }
});

app.listen(PORT, () => {
  const url = process.env.RAILWAY_STATIC_URL
    ? `${process.env.RAILWAY_STATIC_URL}`
    : `http://localhost:${PORT}`;

  console.log(`Сервер запущен: ${url}`);
});
