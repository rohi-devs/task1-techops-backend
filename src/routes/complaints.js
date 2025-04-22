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

router.post(
  "/",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      const { title, description, category } = complaintSchema.parse(req.body);
      let imageUrl = null;

      if (req.file) {
        const blobName = `${Date.now()}-${req.file.originalname}`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
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
      if (error instanceof z.ZodError) {
        return res
          .status(400)
          .json({ message: "Validation error", errors: error.errors });
      }
      res.status(500).json({ message: "Error creating complaint" });
    }
  }
);

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


//   try {
//     const { content } = z
//       .object({ content: z.string().min(1) })
//       .parse(req.body);

//     const complaint = await prisma.complaint.findUnique({
//       where: { id: req.params.id },
//     });

//     if (!complaint) {
//       return res.status(404).json({ message: "Complaint not found" });
//     }

//     if (complaint.userId !== req.user.id) {
//       return res
//         .status(403)
//         .json({ message: "Not authorized to add messages to this complaint" });
//     }

//     const message = await prisma.message.create({
//       data: {
//         content,
//         complaintId: req.params.id,
//       },
//     });

//     res.status(201).json(message);
//   } catch (error) {
//     if (error instanceof z.ZodError) {
//       return res
//         .status(400)
//         .json({ message: "Validation error", errors: error.errors });
//     }
//     res.status(500).json({ message: "Error adding message" });
//   }
// });
router.post("/:id/messages", authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    const complaintId = req.params.id;

    const userId = req.user.id;

    const complaint = await prisma.complaint.findUnique({
      where: { id: complaintId },
    });

    if (!complaint) {
      return res.status(404).json({ message: "Complaint not found" });
    }

    const message = await prisma.message.create({
      data: {
        content,
        complaintId,
        userId,
      },
    });

    res.status(201).json(message);
  } catch (error) {
    console.error("Error posting message:", error);
    res.status(500).json({ message: "Error posting message" });
  }
});

module.exports = router;
