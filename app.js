const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.urlencoded({ extended: true }));

const dbUrl = "mongodb://localhost:27017/jwt-auth-db";
const JWT_SECRET =
  "my-super-secret-authentication-string-agr-tod-sakteho-toh-tod-ke-dikhao";

mongoose.set("strictQuery", true);

main()
  .then(() => {
    console.log("Connected to db");
  })
  .catch((err) => {
    console.log(err);
  });

async function main() {
  await mongoose.connect(dbUrl);
}

//? Model
const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    require: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
});

//? MiddleWare
UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model("User", UserSchema);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; //"Bearer TOKEN"

  if (token == null) {
    return res.status(401).json({ message: "Auth token required" });
  }

  try {
    const decode = jwt.verify(token, JWT_SECRET);
    req.user = decode.user;
    next();
  } catch (err) {
    console.error(err.message);
    res.status(403).json({ message: "invalid or expired token" });
  }
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Access Denied. Admin role required!!" });
  }
  next();
};

//? Auth routes
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res
        .status(400)
        .json({ message: "User with this email already exsist" });
    }

    user = new User({ name, email, password, role });
    await user.save();

    //!Return the ejs templates
    console.log("User registered successfully");
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

//Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid Email" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Password" });
    }

    const payload = {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    };

    jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
      if (err) throw err;
      console.log(`Registered token is:  ${token}`);
      res.json({ token, message: "Login successful" });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.send("Index");
});

app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: `Welcome ${req.user.name}! This is your protected profile.`,
    user: req.user,
  });
});

app.get("/admin/dashboard", authenticateToken, authorizeAdmin, (req, res) => {
  res.json({
    message: `Welcome Admin ${req.user.email}! This is the admin dashboard.`,
    adminDetails: req.user,
  });
});

app.listen(8000, () => {
  console.log("Server is listening to port 8000");
});
