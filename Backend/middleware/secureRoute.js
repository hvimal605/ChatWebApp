const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

exports.secureRoute = async (req, res, next) => {
  try {
    const token = req.cookies.harshcookie;
    console.log("Token received: ", token);
    if (!token) {
      return res.status(401).json({ error: "No token, authorization denied" });
    }
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      if (error instanceof jwt.JsonWebTokenError) {
        return res.status(401).json({ error: "Invalid Token" });
      }
      if (error instanceof jwt.TokenExpiredError) {
        return res.status(401).json({ error: "Token expired" });
      }
      return res.status(500).json({ error: "Internal server error" });
    }
    
    if (!decoded) {
      return res.status(401).json({ error: "Invalid Token" });
    }

    const user = await User.findById(decoded.userId).select("-password");
    if (!user) {
      return res.status(401).json({ error: "No user found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Error in secureRoute: ", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
