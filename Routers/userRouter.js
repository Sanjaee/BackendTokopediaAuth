const router = require("express").Router();
const {
  signUp,
  verifyOtp,
  addName,
  getName,
} = require("../Controllers/userController");

router.route("/signup").post(signUp);
router.route("/signup/verify").post(verifyOtp);
router.route("/signup/name").post(addName);
router.route("/name").get(getName);

module.exports = router;
