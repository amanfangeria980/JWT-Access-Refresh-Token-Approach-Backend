require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { generateAccessToken, generateRefreshToken } = require("./utils");
const app = express();

const corsOptions = {
    origin: "https://jwt-access-refresh-token-approach-frontend.vercel.app/",
    credentials: true,
};
app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));

const PORT = process.env.PORT || 4000;

// Dummy users for demonstration (in a real app, you'd query a database)
const users = [
    { username: "test", password: "test" },
    { username: "ShreyaChauhan", password: "test" },
    { username: "aman", password: "aman" },
];

app.get("/", (req, res) => {
    return res.send(
        "This is the backend server to demonstrate refresh token and access token approach in JWT to make it more secure."
    );
});

app.post("/token", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name });
        const newRefreshToken = generateRefreshToken({ name: user.name });

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            // secure: true,
        });
        res.json({ accessToken });
    });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res
            .status(400)
            .json({ error: "Username and password are required" });
    }

    // Check if the user exists in the dummy users array (for demo purposes)
    const user = users.find(
        (u) => u.username === username && u.password === password
    );
    if (!user) {
        return res.status(403).json({ error: "Invalid username or password" });
    }

    const accessToken = generateAccessToken({ name: user.username });
    const refreshToken = generateRefreshToken({ name: user.username });
    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        // secure: true
    });
    res.json({ accessToken });
});

app.delete("/logout", (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    res.clearCookie("refreshToken");
    res.sendStatus(204);
});

const posts = [
    {
        username: "Shreya",
        title: "Post 1",
    },
    {
        username: "Chauhan",
        title: "Post 2",
    },
];
app.get("/posts", authenticateToken, (req, res) => {
    console.log(req.name, req);
    res.json(posts.filter((post) => post.username === req.name));
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.name = user.name;
        next();
    });
}

app.listen(PORT, () => {
    console.log(`Auth Server is running on PORT:${PORT}`);
});
