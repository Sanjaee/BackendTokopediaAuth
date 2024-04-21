const bcrypt = require("bcrypt");
const _ = require("lodash");
const otpGenerator = require("otp-generator");

// Import model yang diperlukan
const { User } = require("../Model/userModel");
const { Otp } = require("../Model/otpModel");
const NameUser = require("../Model/nameUserModel");

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
  try {
    const { number, otp } = req.body;

    // Cari OTP terkait dari database
    const otpHolder = await Otp.find({ number });

    // Periksa apakah OTP ditemukan
    if (!otpHolder.length)
      return res.status(400).send("You used an expired OTP!");

    // Ambil OTP terbaru
    const rightOtpFind = otpHolder[otpHolder.length - 1];

    // Verifikasi OTP
    const validUser = await bcrypt.compare(otp, rightOtpFind.otp);

    if (rightOtpFind.number === number && validUser) {
      // Generate token JWT
      const user = new User(_.pick(req.body, ["number"]));
      const token = user.generateJWT();
      return res.status(200).send({
        message: "User Registration Successfull!",
        token: token,
      });
    } else {
      return res.status(400).send("Your OTP was wrong!");
    }
  } catch (error) {
    console.error("Error in verifyOtp:", error);
    return res.status(500).send("Internal Server Error");
  }
};

module.exports.addName = async (req, res) => {
  try {
    // Dapatkan nomor, OTP, dan nama dari permintaan
    const { number, otp, name } = req.body;

    // Cek apakah OTP sesuai dengan yang tersimpan
    const otpHolder = await Otp.find({ number });
    if (!otpHolder.length)
      return res.status(400).send("You used an expired OTP!");

    const rightOtpFind = otpHolder[otpHolder.length - 1];
    const validUser = await bcrypt.compare(otp, rightOtpFind.otp);

    if (rightOtpFind.number === number && validUser) {
      // Buat instance baru dari model NameUser dan simpan ke database
      const newUser = new NameUser({ number, otp, name });
      await newUser.save();

      // Setelah berhasil menambahkan nama, buat token JWT
      const token = newUser.generateJWT();

      // Kirim token JWT sebagai respons
      return res.status(200).json({ token });
    } else {
      return res.status(400).send("Your OTP was wrong!");
    }
  } catch (error) {
    console.error("Error in addName:", error);
    return res.status(500).send("Internal Server Error");
  }
};

module.exports.getName = async (req, res) => {
  try {
    // Mengambil semua dokumen dari koleksi NameUser
    const users = await NameUser.find({}, { _id: 1, name: 1 }); // Mengambil field '_id' dan 'name'

    // Jika tidak ada pengguna ditemukan
    if (!users) {
      return res.status(404).json({ message: "No users found." });
    }

    // Mengirimkan data pengguna sebagai respons
    return res.status(200).json(users);
  } catch (error) {
    console.error("Error in getName:", error);
    return res.status(500).send("Internal Server Error");
  }
};
