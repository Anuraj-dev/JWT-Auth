// seed.js
require("dotenv").config();

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./app");

if (!process.env.MONGO_URI) {
  throw new Error("MONGO_URI environment variable is not set. Refusing to seed.");
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
  throw new Error(
    "ADMIN_EMAIL and ADMIN_PASSWORD environment variables must be set. Refusing to seed."
  );
}

const dbUrl = process.env.MONGO_URI;

const createAdmin = async () => {
  try {
    await mongoose.connect(dbUrl);
    console.log("Database connected for seeding.");

    const existingAdmin = await User.findOne({ role: "admin" });
    if (existingAdmin) {
      console.log("Admin user already exists.");
      return;
    }

    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;

    // DO NOT manually hash - let the pre-save hook do it
    const adminUser = new User({
      name: "Admin",
      email: adminEmail,
      password: adminPassword, // Plain password - will be hashed by pre-save hook
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
