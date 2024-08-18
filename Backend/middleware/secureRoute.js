const jwt = require('jsonwebtoken')
const User = require('../models/user.model')



exports.secureRoute = async (req, res, next) => {
  try {
    const token = req.cookies.harshcookie;
    // console.log("token to aagya -->",token)
    if (!token) {
      return res.status(401).json({ error: "No token, authorization denied" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // console.log("ye decoded hai token -->",decoded)
    if (!decoded) {
      return res.status(401).json({ error: "Invalid Token" });
    }
    const user = await User.findById(decoded.userId).select("-password"); // current loggedin user
    // console.log("ye apka current user " , user)
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