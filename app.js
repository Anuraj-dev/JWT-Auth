const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const session = require("express-session");
const flash = require("connect-flash");
const cookieParser = require("cookie-parser");
const ejsMate = require("ejs-mate");

const app = express();

// Configure EJS
app.engine("ejs", ejsMate);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Configure static files
app.use(express.static(path.join(__dirname, "public")));

// Middleware stack
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: "my-super-secret-session-key-change-this-in-production",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 7 * 24 * 60 * 60 * 1000 }, // 7 days
  })
);
app.use(flash());

// Global middleware to make flash messages and user available to all templates
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.currentUser = req.user || null;
  next();
});

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
    required: true,
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
module.exports = User;

//? API Authentication Middleware
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

//? Web Authentication Middleware (for web routes)
const isAuthenticated = (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    req.flash("error_msg", "Please log in to access this page");
    return res.redirect("/login");
  }

  try {
    const decode = jwt.verify(token, JWT_SECRET);
    req.user = decode.user;
    res.locals.currentUser = req.user;
    next();
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Invalid or expired session. Please log in again");
    res.clearCookie("token");
    res.redirect("/login");
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

//? Web Routes (View Routes)
// GET route for registration page
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/", isAuthenticated, (req, res) => {
  res.render("dashboard");
});

app.get("/profile", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      req.flash("error_msg", "User not found");
      return res.redirect("/login");
    }
    res.render("profile", { user });
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Error loading profile");
    res.redirect("/");
  }
});

app.get("/admin/dashboard", isAuthenticated, authorizeAdmin, (req, res) => {
  res.render("admin-dashboard");
});

// Logout route
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.flash("success_msg", "You have been logged out successfully");
  req.session.save((err) => {
    if (err) {
      console.error("Session save error:", err);
    }
    res.redirect("/login");
  });
});

//? Auth routes (POST)
app.post("/register", async (req, res) => {
  const { name, email, password, confirmPassword, role } = req.body;

  // Validation
  if (!email || !password || !name) {
    req.flash("error_msg", "All fields are required");
    return res.redirect("/register");
  }

  if (password !== confirmPassword) {
    req.flash("error_msg", "Passwords do not match");
    return res.redirect("/register");
  }

  if (password.length < 6) {
    req.flash("error_msg", "Password must be at least 6 characters long");
    return res.redirect("/register");
  }

  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash("error_msg", "User with this email already exists");
      return res.redirect("/register");
    }

    user = new User({ name, email, password, role: role || "user" });
    await user.save();

    console.log("User registered successfully");
    req.flash("success_msg", "Registration successful! You can now log in.");
    res.redirect("/login");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Server error. Please try again.");
    res.redirect("/register");
  }
});

//Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    req.flash("error_msg", "Email and password are required");
    return res.redirect("/login");
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      req.flash("error_msg", "Invalid email or password");
      return res.redirect("/login");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      req.flash("error_msg", "Invalid email or password");
      return res.redirect("/login");
    }

    const payload = {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    };

    // Use promisify to avoid callback hell and session context issues
    const token = await new Promise((resolve, reject) => {
      jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
        if (err) reject(err);
        else resolve(token);
      });
    });

    console.log(`Generated token for user: ${user.email}`);

    // Store token in httpOnly cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    req.flash("success_msg", "Login successful! Welcome back.");
    res.redirect("/");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Server error. Please try again.");
    res.redirect("/login");
  }
});

app.listen(8000, () => {
  console.log("Server is listening to port 8000");
});
