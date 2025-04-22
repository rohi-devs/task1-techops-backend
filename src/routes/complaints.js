const express = require("express");
const router = express.Router();
const multer = require("multer");
const { BlobServiceClient } = require("@azure/storage-blob");
const { PrismaClient } = require("@prisma/client");
const { z } = require("zod");
const jwt = require("jsonwebtoken");
const prisma = new PrismaClient();

const blobServiceClient = BlobServiceClient.fromConnectionString(
  process.env.AZURE_STORAGE_CONNECTION_STRING
);
const containerClient = blobServiceClient.getContainerClient(
  process.env.AZURE_STORAGE_CONTAINER_NAME
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

const complaintSchema = z.object({
  title: z.string().min(3).max(100),
  description: z.string().min(10),
  category: z.string(),
});

const messageSchema = z.object({
  content: z.string()
    .min(1, "Message content cannot be empty")
    .max(1000, "Message content too long")
});

const authenticateToken = async (req, res, next) => {
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
    req.user = await prisma.user.findUnique({
      where: { id: decoded.id },
    });

    if (!req.user) {
      return res.status(404).json({ message: "User not found" });
    }

    next();
  } catch (error) {
    console.log(error);
    res.status(401).json({ message: "Invalid token" });
  }
};
router.get("/summary", authenticateToken, async (req, res) => {
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
 * /api/complaints:
 *   post:
 *     summary: Create a new complaint
 *     tags: [Complaints]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - description
 *               - category
 *             properties:
 *               title:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 100
 *               description:
 *                 type: string
 *                 minLength: 10
 *               category:
 *                 type: string
 *               image:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: Complaint created successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */

router.post(
  "/",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    let blockBlobClient = null;
    try {
      const { title, description, category } = complaintSchema.parse(req.body);
      let imageUrl = null;

      if (req.file) {
        const blobName = `${Date.now()}-${req.file.originalname}`;
        blockBlobClient = containerClient.getBlockBlobClient(blobName);
        await blockBlobClient.uploadData(req.file.buffer);
        imageUrl = blockBlobClient.url;
      }

      const complaint = await prisma.complaint.create({
        data: {
          title,
          description,
          category,
          imageUrl,
          userId: req.user?.id,
        },
      });

      res.status(201).json(complaint);
    } catch (error) {
      // Clean up uploaded blob if database operation fails
      if (blockBlobClient) {
        try {
          await blockBlobClient.delete();
        } catch (deleteError) {
          console.error("Error deleting blob:", deleteError);
        }
      }

      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ message: "Validation error", errors: error.errors });
      }

      console.error("Error creating complaint:", error);
      res.status(500).json({ 
        message: "Error creating complaint",
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

/**
 * @swagger
 * /api/complaints:
 *   get:
 *     summary: Get all complaints for the authenticated user
 *     tags: [Complaints]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of complaints
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   title:
 *                     type: string
 *                   description:
 *                     type: string
 *                   status:
 *                     type: string
 *                   messages:
 *                     type: array
 */

router.get("/", authenticateToken, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      where: { userId: req.user.id },
      include: {
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
 * @swagger
 * /api/complaints/{id}:
 *   get:
 *     summary: Get a specific complaint
 *     tags: [Complaints]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Complaint details
 *       403:
 *         description: Not authorized to view this complaint
 *       404:
 *         description: Complaint not found
 */

router.get("/:id", authenticateToken, async (req, res) => {
  try {
    const complaint = await prisma.complaint.findUnique({
      where: { id: req.params.id },
      include: {
        messages: true,
      },
    });

    if (!complaint) {
      return res.status(404).json({ message: "Complaint not found" });
    }

    if (complaint.userId !== req.user.id) {
      return res
        .status(403)
        .json({ message: "Not authorized to view this complaint" });
    }

    res.json(complaint);
  } catch (error) {
    res.status(500).json({ message: "Error fetching complaint" });
  }
});

/**
 * @swagger
 * /api/complaints/{id}/messages:
 *   get:
 *     summary: Get messages for a complaint
 *     tags: [Complaints]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: List of messages
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: string
 *                   content:
 *                     type: string
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *                   senderName:
 *                     type: string
 *                   senderRole:
 *                     type: string
 */

router.get("/:id/messages", authenticateToken, async (req, res) => {
  try {
    const messages = await prisma.message.findMany({
      where: { complaintId: req.params.id },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            role: true,
          },
        },
      },
      orderBy: { createdAt: "asc" },
    });

    const formatted = messages.map((msg) => ({
      id: msg.id,
      content: msg.content,
      createdAt: msg.createdAt,
      senderName: msg.user?.name || "Admin",
      senderRole: msg.user?.role || "ADMIN",
    }));

    res.json(formatted);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});

/**
 * @swagger
 * /api/complaints/{id}/messages:
 *   post:
 *     summary: Add a message to a complaint
 *     tags: [Complaints]
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
 *               - content
 *             properties:
 *               content:
 *                 type: string
 *     responses:
 *       201:
 *         description: Message added successfully
 *       404:
 *         description: Complaint not found
 */

router.post("/:id/messages", authenticateToken, async (req, res) => {
  try {

    const { content } = messageSchema.parse(req.body);
    const complaintId = req.params.id;
    const userId = req.user.id;

 
    const complaint = await prisma.complaint.findUnique({
      where: { id: complaintId },
    });

    if (!complaint) {
      return res.status(404).json({ message: "Complaint not found" });
    }


    if (complaint.userId !== userId) {
      return res.status(403).json({ 
        message: "Not authorized to add messages to this complaint" 
      });
    }


    const message = await prisma.message.create({
      data: {
        content,
        complaintId,
        userId,
      },
      include: {
        user: {
          select: {
            name: true,
            role: true
          }
        }
      }
    });


    res.status(201).json({
      id: message.id,
      content: message.content,
      createdAt: message.createdAt,
      senderName: message.user.name,
      senderRole: message.user.role
    });

  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        }))
      });
    }

    console.error("Error posting message:", error);
    res.status(500).json({ 
      message: "Error posting message",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;
