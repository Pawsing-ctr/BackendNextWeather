const jwt = require("jsonwebtoken");
require("dotenv").config();
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

const generateRefreshToken = async (userId) => {
  const refreshToken = uuidv4();

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  try {
    console.log("Saving refresh token for user:", userId, refreshToken);
    await pool.query(
      "INSERT INTO refresh_tokens (user_id,token,expires_at, revoked) VALUES ($1,$2,$3, false)",
      [userId, refreshToken, expiresAt]
    );

    return refreshToken;
  } catch (error) {
    console.error("Error generating refresh token", error);
    throw error;
  }
};

const verifyRefreshToken = async (token) => {
  try {
    const result = await pool.query(
      "SELECT user_id,expires_at,revoked FROM refresh_tokens WHERE token = $1",
      [token]
    );

    if (result.rows.length === 0) {
      return null;
    }

    const tokenData = result.rows[0];

    if (tokenData.revoked || new Date(tokenData.expires_at) < new Date()) {
      return null;
    }

    const userResult = await pool.query(
      "SELECT id,email,role FROM users WHERE id = $1",
      [tokenData.user_id]
    );

    if (userResult.rows.length === 0) {
      return null;
    }

    return userResult.rows[0];
  } catch (error) {
    console.error("Error verifying refresh token:", error);
    throw error;
  }
};

const revokedRefreshToken = async (token) => {
  try {
    await pool.query(
      "UPDATE refresh_tokens SET revoked = true WHERE token = $1",
      [token]
    );
  } catch (error) {
    console.error("Error revoking refresh token:", error);
    throw error;
  }
};

const revokeAllUserRefreshToken = async (userId) => {
  try {
    await pool.query(
      "UPDATE refresh_tokens SET revoked = true WHERE user_id = $1",
      [userId]
    );
  } catch (error) {
    console.error("Error revoking all user refresh tokens:", error);
    throw error;
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  revokedRefreshToken,
  revokeAllUserRefreshToken,
};
