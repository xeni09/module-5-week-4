const express = require("express");
const router = express.Router();

const posts = require("../controllers/posts.controller");
const users = require("../controllers/users.controller");

const { checkAuth } = require("../middlewares/auth.middlewares");

router.get("/", (req, res) => {
  res.send("Hello from routes");
});

// Posts CRUD
router.post("/posts", checkAuth, posts.create);
router.get("/posts", checkAuth, posts.list);
router.get("/posts/:id", checkAuth, posts.detail);
router.patch("/posts/:id", checkAuth, posts.update);
router.delete("/posts/:id", checkAuth, posts.delete);

// Users CRUD
router.post("/users", users.create);
router.get("/users", users.list);
router.get("/users/verify", users.verify);
router.get("/users/:id", users.detail);
router.patch("/users/:id", users.update);
router.delete("/users/:id", users.delete);

// Authentication
router.post("/login", users.login);

module.exports = router;
