const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

exports.secureRoute = async (req, res, next) => {
  try {
    const token = req.cookies.harshcookie;
    console.log("Token received:", token);
    
    if (!token) {
      return res.status(401).json({ error: "No token, authorization denied" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if (err) {
        console.log("Token verification error:", err);
        return res.status(401).json({ error: "Invalid Token" });
      }
      return decodedToken;
    });
    
    if (!decoded) {
      return res.status(401).json({ error: "Invalid Token" });
    }

    const user = await User.findById(decoded.userId).select("-password"); 
    console.log("Current user found:", user);

    if (!user) {
      return res.status(401).json({ error: "No user found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Error in secureRoute:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};
