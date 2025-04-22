const express = require("express");
const router = express.Router();
const { PrismaClient } = require("@prisma/client");
const { z } = require("zod");
const jwt = require("jsonwebtoken");
const prisma = new PrismaClient();
const bcrypt = require("bcrypt");
const JWT_SECRET = process.env.JWT_SECRET;

const multer = require("multer");
const storage = multer.memoryStorage();
const upload = multer({ storage });

const updateProfileSchema = z.object({
  name: z.string().min(2).max(50).optional(),
  email: z.string().email().optional(),
  password: z.string().min(6).optional(),
});

const userLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const registerSchema = z.object({
  name: z.string().min(2).max(50),
  email: z.string().email(),
  password: z.string().min(4),
});

router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = registerSchema.parse(req.body);

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
      },
    });

    res
      .status(201)
      .json({ message: "User registered successfully", userId: user.id });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation failed", errors: error.errors });
    }
    console.log(error);
    res.status(500).json({ message: "Registration failed" });
  }
});
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    console.log("token", token);
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("decoded", decoded);
    const admin = await prisma.user.findUnique({
      where: { id: decoded.id },
    });
    console.log(admin);
    req.user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!req.user) {
      return res.status(404).json({ message: "User not found" });
    }

    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

router.get("/profile", authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Error fetching profile" });
  }
});

router.put("/profile", authenticateToken, async (req, res) => {
  console.log(req.body);
  try {
    const { name, email, password } = updateProfileSchema.parse(req.body);
    const updateData = {};
    if (name) updateData.name = name;
    if (email) updateData.email = email;
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }
    console.log(updateData);

    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: updateData,
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    res.json(updatedUser);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Error updating profile" });
  }
});

router.delete("/profile", authenticateToken, async (req, res) => {
  try {
    await prisma.user.delete({
      where: { id: req.user.id },
    });

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: "Error deleting profile" });
  }
});

router.get("/summary", authenticateToken, async (req, res) => {
  try {
    const complaints = await prisma.complaint.groupBy({
      by: ["status"],
      where: { userId: req.user.id },
      _count: true,
    });
    console.log(complaints)
    const summary = {
      total: complaints.reduce((acc, curr) => acc + curr._count, 0),
      pending: complaints.find((c) => c.status === "PENDING")?._count || 0,
      inProgress:
        complaints.find((c) => c.status === "IN_PROGRESS")?._count || 0,
      resolved: complaints.find((c) => c.status === "RESOLVED")?._count || 0,
    };
    console.log(summary)
    res.json(summary);
  } catch (error) {
    res.status(500).json({ message: "Error fetching summary" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = userLoginSchema.parse(req.body);

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const tokenPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, {
      expiresIn: "24h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "Lax",
    });

    res.json({ message: "Login successful" });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    res.status(500).json({ message: "Error logging in" });
  }
});

router.get("/me", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ user: null });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    //console.log("user",user);
    res.json({ user,token });
  } catch (Error) {
    console.log(Error);
    res.clearCookie("token");
    res.json({ user: null });
  }
});

router.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    sameSite: "Lax",
    secure: true,
  });
  res.json({ success: true });
});

module.exports = router;
