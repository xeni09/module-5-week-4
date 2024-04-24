require("dotenv").config();

const express = require("express");
const app = express();

require("./config/db.config");

app.use(express.json()); // para que express entienda los json, el body, por ejemplo

const router = require("./config/routes.config");
app.use(router);

app.listen(8000, () => {
  console.log("Ready in port 8000");
});
