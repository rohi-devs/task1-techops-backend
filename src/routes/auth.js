const express = require("express");
const router = express.Router();
const { PrismaClient } = require("@prisma/client");
const { z } = require("zod");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { OAuth2Client } = require("google-auth-library");
const prisma = new PrismaClient();
const CLIENT_ID =
  "508689776836-1nsaglsj080gi5gfkafaap2k9e69g5ne.apps.googleusercontent.com";
const JWT_SECRET = process.env.JWT_SECRET;
const client = new OAuth2Client(CLIENT_ID);
const adminLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

const createAdminSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  password: z.string().min(6),
  role: z.enum(["MODERATOR", "SUPER_ADMIN"]),
});

const updateComplaintSchema = z.object({
  status: z.enum(["PENDING", "IN_PROGRESS", "RESOLVED"]),
  response: z.string().optional(),
});

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication endpoints
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login as admin
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 minLength: 6
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     email:
 *                       type: string
 *                     name:
 *                       type: string
 *                     role:
 *                       type: string
 *       401:
 *         description: Invalid credentials
 */

/**
 * @swagger
 * /api/auth/create:
 *   post:
 *     summary: Create a new admin user
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - name
 *               - password
 *               - role
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               name:
 *                 type: string
 *                 minLength: 2
 *               password:
 *                 type: string
 *                 minLength: 6
 *               role:
 *                 type: string
 *                 enum: [MODERATOR, SUPER_ADMIN]
 *     responses:
 *       201:
 *         description: Admin created successfully
 *       403:
 *         description: Only Super Admin can create new admins
 */

/**
 * @swagger
 * /api/auth/complaints:
 *   get:
 *     summary: Get all complaints
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of all complaints
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   user:
 *                     type: object
 *                   messages:
 *                     type: array
 */

/**
 * @swagger
 * /api/auth/complaints/{id}:
 *   put:
 *     summary: Update complaint status
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [PENDING, IN_PROGRESS, RESOLVED]
 *               response:
 *                 type: string
 *     responses:
 *       200:
 *         description: Complaint updated successfully
 */

/**
 * @swagger
 * /api/auth/statistics:
 *   get:
 *     summary: Get complaint statistics
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Complaint statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 total:
 *                   type: number
 *                 byStatus:
 *                   type: array
 *                 byCategory:
 *                   type: array
 */

/**
 * @swagger
 * /api/auth/admins:
 *   get:
 *     summary: Get all admin users
 *     tags: [Auth]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of all admin users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   email:
 *                     type: string
 *                   name:
 *                     type: string
 *                   role:
 *                     type: string
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *       403:
 *         description: Only Super Admin can view all admins
 */

/**
 * @swagger
 * /api/auth/google:
 *   post:
 *     summary: Authenticate with Google
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - credential
 *             properties:
 *               credential:
 *                 type: string
 *     responses:
 *       200:
 *         description: Authentication successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       401:
 *         description: Invalid token
 */

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (
      !admin ||
      (admin.role !== "MODERATOR" && admin.role !== "SUPER_ADMIN")
    ) {
      return res.status(403).json({ message: "Not authorized" });
    }

    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

router.post("/login", async (req, res) => {
  try {
    const { email, password } = adminLoginSchema.parse(req.body);

    const admin = await prisma.user.findUnique({
      where: { email },
    });

    if (
      !admin ||
      (admin.role !== "MODERATOR" && admin.role !== "SUPER_ADMIN")
    ) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: admin.id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      token,
      user: {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: admin.role,
      },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    res.status(500).json({ message: "Error logging in" });
  }
});

router.post("/create", authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== "SUPER_ADMIN") {
      return res
        .status(403)
        .json({ message: "Only Super Admin can create new admins" });
    }

    const { email, name, password, role } = createAdminSchema.parse(req.body);

    const hashedPassword = await bcrypt.hash(password, 10);

    const newAdmin = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword,
        role,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    res.status(201).json(newAdmin);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    res.status(500).json({ message: "Error creating admin" });
  }
});

router.get("/complaints", authenticateAdmin, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        messages: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(complaints);
  } catch (error) {
    res.status(500).json({ message: "Error fetching complaints" });
  }
});

router.put("/complaints/:id", authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = updateComplaintSchema.parse(req.body);
    console.log(status,response)
    const complaint = await prisma.complaint.update({
      where: { id: req.params.id },
      data: { status },
    });

    if (response) {
      console.log("response created")
      await prisma.message.create({
        data: {
          content: response,
          complaintId: complaint.id,
        },
      });
    }

    res.json(complaint);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    res.status(500).json({ message: "Error updating complaint" });
  }
});

router.get("/statistics", authenticateAdmin, async (req, res) => {
  try {
    const totalComplaints = await prisma.complaint.count();
    const complaintsByStatus = await prisma.complaint.groupBy({
      by: ["status"],
      _count: true,
    });
    const complaintsByCategory = await prisma.complaint.groupBy({
      by: ["category"],
      _count: true,
    });

    res.json({
      total: totalComplaints,
      byStatus: complaintsByStatus,
      byCategory: complaintsByCategory,
    });
  } catch (error) {
    res.status(500).json({ message: "Error fetching statistics" });
  }
});

router.get("/admins", authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== "SUPER_ADMIN") {
      return res
        .status(403)
        .json({ message: "Only Super Admin can view all admins" });
    }

    const admins = await prisma.user.findMany({
      where: {
        role: {
          in: ["MODERATOR", "SUPER_ADMIN"],
        },
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    res.json(admins);
  } catch (error) {
    res.status(500).json({ message: "Error fetching admins" });
  }
});


router.post("/google", async (req, res) => {
  const { credential } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, picture, sub } = payload;

    let user = await prisma.user.findUnique({
      where: { email },
    });

    const bcrypt = require("bcrypt");
    const saltRounds = 10;

    if (!user) {
      const name = email.split("@")[0];
      const hashedPassword = await bcrypt.hash("google-auth", saltRounds);

      user = await prisma.user.create({
        data: {
          email,
          name,
          password: hashedPassword,
        },
      });
    }

    const tokenPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "24h" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "None",
    });

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(401).json({ success: false, message: "Invalid token" });
  }
});

module.exports = router;
