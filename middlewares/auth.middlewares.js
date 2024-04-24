const jwt = require("jsonwebtoken");

module.exports.checkAuth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split("Bearer ")[1];

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ err });
  }
};
