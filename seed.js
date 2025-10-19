// seed.js
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./app");

const dbUrl = "mongodb://localhost:27017/jwt-auth-db";

const createAdmin = async () => {
  try {
    await mongoose.connect(dbUrl);
    console.log("Database connected for seeding.");

    const existingAdmin = await User.findOne({ role: "admin" });
    if (existingAdmin) {
      console.log("Admin user already exists.");
      return;
    }

    const adminEmail = "admin@example.com";
    const adminPassword = "admin123";

    // Manually hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminPassword, salt);

    const adminUser = new User({
      name: "Admin",
      email: adminEmail,
      password: hashedPassword,
      role: "admin",
    });

    await adminUser.save();
    console.log("✅ Admin user created successfully!");
    console.log(`Email: ${adminEmail}`);
    console.log(`Password: ${adminPassword} (Change after first login!)`);
  } catch (error) {
    console.error("Error seeding admin user:", error);
  } finally {
    await mongoose.disconnect();
    console.log("Database disconnected.");
  }
};
createAdmin();
