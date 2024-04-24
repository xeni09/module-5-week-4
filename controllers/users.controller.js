const User = require("../models/user.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

module.exports.verify = (req, res) => {
  const token = req.query.token;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    User.findByIdAndUpdate(decoded.sub, { active: true }, { new: true }).then(
      (user) => {
        if (user) {
          res
            .status(200)
            .json({ message: "User verified correctly", user: user });
        } else {
          res.status(404).json({ message: "User not found" });
        }
      }
    );
  } catch (err) {
    console.error(err);
    res.status(401).json({ message: "Unable to verify" });
  }
};

module.exports.create = (req, res) => {
  User.create(req.body)
    .then((user) => {
      const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET);
      const verifyUrl = `http://localhost:8000/users/verify?token=${token}`;

      // Todo: Send email with verification link
      console.log(verifyUrl);

      res.status(201).json(user);
    })
    .catch((err) => {
      console.error(err);
      res.status(400).json(err);
    });
};

module.exports.list = (req, res) => {
  User.find()
    .then((users) => {
      if (users.length === 0) {
        res
          .status(200)
          .json({ message: "No users found, please create one first" });
      } else {
        res.status(200).json(users);
      }
    })
    .catch(console.error);
};

module.exports.detail = (req, res) => {
  User.findById(req.params.id)
    .then((user) => {
      if (user) {
        res.status(200).json(user);
      } else {
        res.status(404).json({ message: "User not found" });
      }
    })
    .catch(console.error);
};

module.exports.update = (req, res) => {
  User.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
    runValidators: true,
  })
    .then((user) => {
      if (user) {
        res.status(200).json(user);
      } else {
        res.status(404).json({ message: "User not found" });
      }
    })
    .catch((err) => {
      console.error(err);
      res.status(400).json(err);
    });
};

module.exports.delete = (req, res) => {
  User.findByIdAndDelete(req.params.id)
    .then((user) => {
      if (user) {
        res.status(200).json({
          message: `User with ID ${req.params.id} has been deleted correctly.`,
        });
      } else {
        res.status(404).json({ message: "User not found" });
      }
    })
    .catch(console.error);
};

module.exports.login = (req, res) => {
  User.findOne({ email: req.body.email })
    .then(async (user) => {
      if (
        user &&
        user.active &&
        (await bcrypt.compare(req.body.password, user.password))
      ) {
        const token = jwt.sign(
          {
            sub: user.id,
            exp: Date.now() / 1000 + 120,
          },
          process.env.JWT_SECRET
        );
        res.json({ token });
      } else if (user && !user.active) {
        res.status(401).json({ message: "User has not been yet actived" });
      } else {
        res
          .status(401)
          .json({ message: "Invalid credentials or User doesn't exist" });
      }
    })
    .catch((err) => {
      console.error(err);
      res.status(400).json({ message: "Error in data validation" });
    });
};
