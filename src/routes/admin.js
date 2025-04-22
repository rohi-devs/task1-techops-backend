const express = require("express");
const router = express.Router();
const { PrismaClient } = require("@prisma/client");
const { z } = require("zod");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const prisma = new PrismaClient();

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

const authenticateAdmin = async (req, res, next) => {
  console.log("req", req.headers);
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

/**
 * @swagger
 * /api/admin/login:
 *   post:
 *     summary: Login for admin users
 *     tags: [Admin]
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

/**
 * @swagger
 * /api/admin/create:
 *   post:
 *     summary: Create a new admin user
 *     tags: [Admin]
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
router.post("/create", authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== "SUPER_ADMIN") {
      return res
        .status(403)
        .json({ message: "Only Super Admin can create new admins" });
    }

    console.log(req.body.role);
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
    console.log(error);
    if (error instanceof z.ZodError) {
      return res
        .status(400)
        .json({ message: "Validation error", errors: error.errors });
    }
    res.status(500).json({ message: "Error creating admin" });
  }
});

/**
 * @swagger
 * /api/admin/complaints:
 *   get:
 *     summary: Get all complaints
 *     tags: [Admin]
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

/**
 * @swaggerconst options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Admin API Documentation',
      version: '1.0.0',
      description: 'API documentation for the admin routes',
    },
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.js'], // path to your API routes
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
 * /api/admin/complaints/{id}:
 *   put:
 *     summary: Update complaint status and add response
 *     tags: [Admin]
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
router.put("/complaints/:id", authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = updateComplaintSchema.parse(req.body);
    console.log(status, response);
    const complaint = await prisma.complaint.update({
      where: { id: req.params.id },
      data: { status },
    });
    const userId = req.admin.id;
    if (response) {
      console.log("response created");
      await prisma.message.create({
        data: {
          content: response,
          complaintId: complaint.id,
          userId
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

/**
 * @swagger
 * /api/admin/statistics:
 *   get:
 *     summary: Get complaints statistics
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Complaints statistics
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

/**
 * @swagger
 * /api/admin/summary:
 *   get:
 *     summary: Get complaints summary
 *     tags: [Admin]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Complaints summary
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 summary:
 *                   type: object
 *                 groupedComplaints:
 *                   type: object
 */
router.get("/summary", authenticateAdmin, async (req, res) => {
  console.log("summary admin");
  try {
    const complaints = await prisma.complaint.findMany({
      select: {
        title: true,
        status: true,
      },
    });

    const groupedComplaints = complaints.reduce((acc, complaint) => {
      const status = complaint.status;
      if (!acc[status]) {
        acc[status] = { titles: [], count: 0 };
      }
      acc[status].titles.push(complaint.title);
      acc[status].count += 1;
      return acc;
    }, {});

    const summary = {
      total: complaints.length,
      pending: groupedComplaints.PENDING?.count || 0,
      inProgress: groupedComplaints.IN_PROGRESS?.count || 0,
      resolved: groupedComplaints.RESOLVED?.count || 0,
    };

    res.json({
      summary,
      groupedComplaints,
    });
  } catch (error) {
    res.status(500).json({ message: "Error fetching summary" });
  }
});

/**
 * @swagger
 * /api/admin/admins:
 *   get:
 *     summary: Get all admin users
 *     tags: [Admin]
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

module.exports = router;
