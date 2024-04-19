const bcrypt = require("bcrypt");
const _ = require("lodash");
const axios = require("axios");
const otpGenerator = require("otp-generator");

// Import model yang diperlukan
const { User } = require("../Model/userModel");
const { Otp } = require("../Model/otpModel");

// Import variabel lingkungan
require("dotenv").config();
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID;
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_NUMBER;

// Cek apakah variabel lingkungan sudah terisi
if (!twilioAccountSid || !twilioAuthToken || !twilioPhoneNumber) {
  console.error("Please set up Twilio environment variables properly.");
  process.exit(1);
}

// Inisialisasi Twilio client dengan akun SID dan token otentikasi
const client = require("twilio")(twilioAccountSid, twilioAuthToken);

// Fungsi untuk mengirim SMS menggunakan Twilio
const sendSMS = async (to, body) => {
  let msgOptions = {
    from: twilioPhoneNumber,
    to: `${to}`, // Format nomor untuk Twilio
    body: body,
  };
  try {
    const message = await client.messages.create(msgOptions);
    console.log(message);
  } catch (err) {
    console.error("Error sending SMS:", err);
    throw new Error("Failed to send SMS");
  }
};

// Fungsi untuk proses pendaftaran
module.exports.signUp = async (req, res) => {
  try {
    const user = await User.findOne({ number: req.body.number });
    if (user) return res.status(400).send("User already registered!");

    const OTP = otpGenerator.generate(6, {
      digits: true,
      alphabets: false,
      upperCase: false,
      specialChars: false,
    });

    const number = req.body.number;
    await sendSMS(number, `Verification Code: ${OTP}`);

    const salt = await bcrypt.genSalt(10);
    const hashedOTP = await bcrypt.hash(OTP, salt);

    // Simpan data nomor dan OTP ke koleksi otps
    const otp = new Otp({ number: number, otp: hashedOTP });
    await otp.save();

    return res.status(200).send("OTP sent successfully!");
  } catch (error) {
    console.error("Error in signUp:", error);
    return res.status(500).send("Internal Server Error");
  }
};

// Fungsi untuk memverifikasi OTP
module.exports.verifyOtp = async (req, res) => {
  const otpHolder = await Otp.find({
    number: req.body.number,
  });
  if (otpHolder.length === 0)
    return res.status(400).send("You use an Expired OTP!");
  const rightOtpFind = otpHolder[otpHolder.length - 1];
  const validUser = await bcrypt.compare(req.body.otp, rightOtpFind.otp);

  if (rightOtpFind.number === req.body.number && validUser) {
    const user = new User(_.pick(req.body, ["number"]));
    const token = user.generateJWT();
    const result = await user.save();
    const OTPDelete = await Otp.deleteMany({
      number: rightOtpFind.number,
    });
    return res.status(200).send({
      message: "User Registration Successfull!",
      token: token,
      data: result,
    });
  } else {
    return res.status(400).send("Your OTP was wrong!");
  }
};
