const jwt=require('jsonwebtoken')

function generateRefreshToken(user) {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: process.env.REFRESH_TOKEN_EXPIRATION });
  }

function generateAccessToken(user){
    return jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn : process.env.ACCESS_TOKEN_EXPIRATION})
}


 module.exports={generateAccessToken,generateRefreshToken}