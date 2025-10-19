const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const session = require("express-session");
const flash = require("connect-flash");
const cookieParser = require("cookie-parser");
const ejsMate = require("ejs-mate");
const methodOverride = require("method-override");
const expressError = require("./utils/AppError");
const wrapAsync = require("./utils/wrapAsync");

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
app.use(methodOverride("_method"));
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
    req.flash("error_msg", "Access Denied. Admin role required!");
    return res.redirect("/");
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
  // Redirect users directly to their profile and admins to the admin dashboard
  if (req.user && req.user.role === "admin") {
    return res.redirect("/admin/dashboard");
  }
  return res.redirect("/profile");
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

app.get("/profile/edit", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      req.flash("error_msg", "User not found");
      return res.redirect("/login");
    }
    res.render("edit-profile", { user });
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Error loading profile");
    res.redirect("/");
  }
});

app.put("/profile/edit", isAuthenticated, async (req, res) => {
  const { name, email, currentPassword, newPassword, confirmNewPassword } =
    req.body;

  if (!name || !email) {
    req.flash("error_msg", "Name and email are required");
    return res.redirect("/profile/edit");
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      req.flash("error_msg", "User not found");
      return res.redirect("/login");
    }

    // Check if email is being changed and if it's already taken
    if (email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        req.flash("error_msg", "Email is already in use");
        return res.redirect("/profile/edit");
      }
    }

    user.name = name;
    user.email = email;

    if (currentPassword || newPassword || confirmNewPassword) {
      if (!currentPassword) {
        req.flash(
          "error_msg",
          "Current password is required to change password"
        );
        return res.redirect("/profile/edit");
      }

      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        req.flash("error_msg", "Current password is incorrect");
        return res.redirect("/profile/edit");
      }

      if (!newPassword || !confirmNewPassword) {
        req.flash("error_msg", "Please enter and confirm your new password");
        return res.redirect("/profile/edit");
      }

      if (newPassword !== confirmNewPassword) {
        req.flash("error_msg", "New passwords do not match");
        return res.redirect("/profile/edit");
      }

      if (newPassword.length < 6) {
        req.flash("error_msg", "Password must be at least 6 characters long");
        return res.redirect("/profile/edit");
      }

      user.password = newPassword;
    }

    await user.save();

    const payload = {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    };

    const token = await new Promise((resolve, reject) => {
      jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
        if (err) reject(err);
        else resolve(token);
      });
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    req.flash("success_msg", "Profile updated successfully!");
    res.redirect("/profile");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Error updating profile");
    res.redirect("/profile/edit");
  }
});

// DELETE route
app.delete("/profile/delete", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      req.flash("error_msg", "User not found");
      return res.redirect("/login");
    }

    if (user.role === "admin") {
      req.flash(
        "error_msg",
        "Admin accounts cannot be deleted for security reasons"
      );
      return res.redirect("/profile");
    }

    await User.findByIdAndDelete(req.user.id);

    res.clearCookie("token");
    req.flash("success_msg", "Your account has been deleted successfully");
    res.redirect("/register");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Error deleting account");
    res.redirect("/profile");
  }
});

app.get(
  "/admin/dashboard",
  isAuthenticated,
  authorizeAdmin,
  async (req, res) => {
    try {
      // fetch users for admin view (omit passwords)
      const users = await User.find().select("-password").lean();
      res.render("admin-dashboard", { users });
    } catch (err) {
      console.error(err.message);
      req.flash("error_msg", "Error loading admin dashboard");
      res.redirect("/");
    }
  }
);

// Admin: Add user form
app.get("/admin/users/new", isAuthenticated, authorizeAdmin, (req, res) => {
  res.render("admin-add-user");
});

// Admin: Create new user
app.post("/admin/users", isAuthenticated, authorizeAdmin, async (req, res) => {
  const { name, email, password, confirmPassword, role } = req.body;

  // Validation
  if (!name || !email || !password || !confirmPassword) {
    req.flash("error_msg", "All fields are required");
    return res.redirect("/admin/users/new");
  }

  if (password !== confirmPassword) {
    req.flash("error_msg", "Passwords do not match");
    return res.redirect("/admin/users/new");
  }

  if (password.length < 6) {
    req.flash("error_msg", "Password must be at least 6 characters long");
    return res.redirect("/admin/users/new");
  }

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash("error_msg", "User with this email already exists");
      return res.redirect("/admin/users/new");
    }

    // Create new user
    const newUser = new User({
      name,
      email,
      password,
      role: role === "admin" ? "admin" : "user",
    });

    await newUser.save();

    req.flash(
      "success_msg",
      `User ${name} created successfully as ${
        role === "admin" ? "Admin" : "User"
      }`
    );
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Error creating user. Please try again.");
    res.redirect("/admin/users/new");
  }
});

// Admin: Edit user form (only for regular users, not admins)
app.get(
  "/admin/users/:id/edit",
  isAuthenticated,
  authorizeAdmin,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select("-password");
      if (!user) {
        req.flash("error_msg", "User not found");
        return res.redirect("/admin/dashboard");
      }

      // Prevent editing admin accounts via GUI
      if (user.role === "admin") {
        req.flash("error_msg", "Admin accounts can only be edited via code");
        return res.redirect("/admin/dashboard");
      }

      res.render("admin-edit-user", { user });
    } catch (err) {
      console.error(err.message);
      req.flash("error_msg", "Error loading edit form");
      res.redirect("/admin/dashboard");
    }
  }
);

// Admin: Update user (only regular users, not admins)
app.put(
  "/admin/users/:id",
  isAuthenticated,
  authorizeAdmin,
  async (req, res) => {
    const { name, email, role, newPassword, confirmNewPassword } = req.body;
    try {
      const user = await User.findById(req.params.id);
      if (!user) {
        req.flash("error_msg", "User not found");
        return res.redirect("/admin/dashboard");
      }

      // Prevent editing admin accounts via GUI
      if (user.role === "admin") {
        req.flash("error_msg", "Admin accounts can only be edited via code");
        return res.redirect("/admin/dashboard");
      }

      if (!name || !email) {
        req.flash("error_msg", "Name and email are required");
        return res.redirect(`/admin/users/${req.params.id}/edit`);
      }

      // If email changed, ensure uniqueness
      if (email !== user.email) {
        const existing = await User.findOne({ email });
        if (existing) {
          req.flash("error_msg", "Email is already in use");
          return res.redirect(`/admin/users/${req.params.id}/edit`);
        }
      }

      user.name = name;
      user.email = email;
      user.role = role === "admin" ? "admin" : "user";

      if (newPassword || confirmNewPassword) {
        if (newPassword !== confirmNewPassword) {
          req.flash("error_msg", "New passwords do not match");
          return res.redirect(`/admin/users/${req.params.id}/edit`);
        }
        if (newPassword.length < 6) {
          req.flash("error_msg", "Password must be at least 6 characters long");
          return res.redirect(`/admin/users/${req.params.id}/edit`);
        }
        user.password = newPassword; // will be hashed by pre-save hook
      }

      await user.save();
      req.flash("success_msg", "User updated successfully");
      res.redirect("/admin/dashboard");
    } catch (err) {
      console.error(err.message);
      req.flash("error_msg", "Error updating user");
      res.redirect("/admin/dashboard");
    }
  }
);

// Admin: Delete user
app.delete(
  "/admin/users/:id",
  isAuthenticated,
  authorizeAdmin,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) {
        req.flash("error_msg", "User not found");
        return res.redirect("/admin/dashboard");
      }

      // Prevent deleting admin accounts for safety
      if (user.role === "admin") {
        req.flash("error_msg", "Admin accounts cannot be deleted");
        return res.redirect("/admin/dashboard");
      }

      await User.findByIdAndDelete(req.params.id);
      req.flash("success_msg", "User deleted successfully");
      res.redirect("/admin/dashboard");
    } catch (err) {
      console.error(err.message);
      req.flash("error_msg", "Error deleting user");
      res.redirect("/admin/dashboard");
    }
  }
);

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

    const token = await new Promise((resolve, reject) => {
      jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" }, (err, token) => {
        if (err) reject(err);
        else resolve(token);
      });
    });

    console.log(`Generated token for user: ${user.email}`);

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Personalized welcome message
    if (user.role === "admin") {
      req.flash("success_msg", `Welcome back, Admin ${user.name}!`);
    } else {
      req.flash("success_msg", `Welcome back, ${user.name}!`);
    }

    res.redirect("/");
  } catch (err) {
    console.error(err.message);
    req.flash("error_msg", "Server error. Please try again.");
    res.redirect("/login");
  }
});

// Test routes for error pages (can be removed in production)
app.get("/test-error/:code", (req, res, next) => {
  const code = parseInt(req.params.code);
  const messages = {
    400: "Bad Request - The data you sent doesn't look right",
    401: "Unauthorized - You need to log in first",
    403: "Forbidden - You don't have permission to access this",
    404: "Not Found - This page doesn't exist",
    500: "Internal Server Error - Something broke on our server",
  };

  const error = new expressError(code, messages[code] || "An error occurred");
  next(error);
});

// 404 Handler - Catch all undefined routes
app.use((req, res, next) => {
  const error = new expressError(404, `Page not found - ${req.originalUrl}`);
  next(error);
});

// Global Error Handler
app.use((err, req, res, next) => {
  // Set default values
  const statusCode = err.status || 500;
  const message = err.message || "Something went wrong on our server";
  const stack = err.stack;

  console.error("Error:", {
    statusCode,
    message,
    stack: process.env.NODE_ENV === "development" ? stack : undefined,
    url: req.originalUrl,
    method: req.method,
  });

  res.status(statusCode).render("error", {
    statusCode,
    message,
    stack: process.env.NODE_ENV === "development" ? stack : undefined,
  });
});

app.listen(8000, () => {
  console.log("Server is listening to port 8000");
});
