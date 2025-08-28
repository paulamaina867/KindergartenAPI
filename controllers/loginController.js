// Import the user schema
const { User } = require("../models/schoolDb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// import the jwt secret key from .env file
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY;

// Controller to register an admin
exports.registerAdmin = async (req, res) => {
  try {
    const { name, email, password, secretKey } = req.body;

    // 1. Verify the admin secret Key
    if (!secretKey || secretKey !== ADMIN_SECRET_KEY) {
      return res.status(403).json({ message: "Unauthorized Account Creation" });
    }

    // 2. Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this email address already exists" });
    }

    // 3. Create the admin user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role: "admin",
      isActive: true,
      teacher: null,
      parent: null,
    });

    const user = await newUser.save();

    res
      .status(201)
      .json({ message: "Admin account created successfully", user });
  } catch (err) {
    res.status(500).json({ message: "Error creating admin", error: err.message });
  }
};

// Login route
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Check email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Email address could not be found." });
    }

    // 2. Check active status
    if (!user.isActive) {
      return res.status(403).json({ message: "Your account has been deactivated" });
    }

    // 3. Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid password." });
    }

    // 4. Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: "4h" }
    );

    // 5. Success
    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    res.status(500).json({ message: "Login Failed", error: err.message });
  }
};
