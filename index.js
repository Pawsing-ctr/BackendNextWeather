const express = require("express");
const cors = require("cors");
const { Pool, Client } = require("pg");
require("dotenv").config();
const bcrypt = require("bcrypt");

const user = process.env.USER;
const database = process.env.DATABASE;
const password = process.env.PASSWORD;

const app = express();
const PORT = 3010;

app.use(cors());
app.use(express.json());

const pool = new Pool({
  user,
  host: "localhost",
  database,
  password,
  port: 5432,
});

app.post("/api/users", async (req, res) => {
  console.log("Received registration request:", req.body);
  const { email, password, day, month, year } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

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

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (email, password, day, month, year) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, day, month, year",
      [email, passwordHash, day, month, year]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "User registered successfully!",
      data: {
        id: user.id,
        email: user.email,
        day: user.day,
        month: user.month,
        year: user.year,
      },
    });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Сервер запущен: http://localhost:${PORT}`);
});
