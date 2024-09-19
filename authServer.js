require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
app.use(express.json());
app.use(cookieParser());
const { generateAccessToken, generateRefreshToken } = require("./utils");

const PORT = process.env.AUTH_SERVER_PORT || 4000;
// let refreshTokens = [];

app.post("/token", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    // if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name });
        const newRefreshToken = generateRefreshToken({ name: user.name });

        // refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        // refreshTokens.push(newRefreshToken);

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
        });
        res.json({ accessToken });
    });
});

app.post("/login", (req, res) => {
    const username = req.body.username;
    if (!username)
        return res.status(400).json({ error: "Username is required" });
    const user = { name: username };
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    // refreshTokens.push(refreshToken);
    res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: true });
    res.json({ accessToken });
});

app.delete("/logout", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    // refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
    res.clearCookie("refreshToken");
    res.sendStatus(204);
});

app.listen(PORT, () => {
    console.log(`Auth Server is running on PORT:${PORT}`);
});
