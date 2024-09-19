require("dotenv").config();
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const { generateRefreshToken,generateAccessToken } = require("./utils");
app.use(express.json());
const PORT=process.env.AUTH_SERVER_PORT || 4000;

let refreshTokens = [];

app.post("/token", (req, res) => {
  let refreshToken = req.headers['refreshtoken'].split(' ')[1];
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.status(403).send("Wrong refresh token");

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const newRefreshToken =generateRefreshToken({name: user.name}) 
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    refreshTokens.push(newRefreshToken);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken, refreshToken: newRefreshToken });
  });
  
});



app.post("/login", (req, res) => {
  //AUTHENTICATE USER
  const username = req.body.username;
  const user = { name: username };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  res.json({ accessToken: accessToken, refreshToken: refreshToken });
  refreshTokens.push(refreshToken);
});


app.delete("/logout", (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
});



app.listen(PORT,()=>{
    console.log(`Server is running on PORT:${PORT}`)
});
