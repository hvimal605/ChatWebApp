const jwt = require("jsonwebtoken");

exports.createTokenAndSaveCookie = (userId, res) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "10d",
  });

  // Set the cookie with the JWT token
  res.cookie("harshcookie", token, {
    httpOnly: true,
    secure: true,        
    sameSite: "None"     
  });
};


