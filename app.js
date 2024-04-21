const express = require("express");
const cors = require("cors");
const app = express();
const userRouter = require("./Routers/userRouter");
app.use(express.json());

app.use(cors());

app.use("/api/user", userRouter);

module.exports = app;
