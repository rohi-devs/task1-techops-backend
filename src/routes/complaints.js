const express = require('express');
const router = express.Router();
const multer = require('multer');
const { BlobServiceClient } = require('@azure/storage-blob');
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');

const prisma = new PrismaClient();


const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);
const containerClient = blobServiceClient.getContainerClient(process.env.AZURE_STORAGE_CONTAINER_NAME);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024 
  }
});

const complaintSchema = z.object({
  title: z.string().min(3).max(100),
  description: z.string().min(10),
  category: z.string()
});

const authenticateToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await prisma.user.findUnique({
      where: { id: decoded.userId }
    });

    if (!req.user) {
      return res.status(404).json({ message: 'User not found' });
    }

    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};


router.post('/', authenticateToken, upload.single('image'), async (req, res) => {
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
        userId: req.user.id
      }
    });

    res.status(201).json(complaint);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error creating complaint' });
  }
});


router.get('/', authenticateToken, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      where: { userId: req.user.id },
      include: {
        messages: true
      },
      orderBy: {
        createdAt: 'desc'
      }
    });

    res.json(complaints);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching complaints' });
  }
});

router.get('/:id', authenticateToken, async (req, res) => {
  try {
    const complaint = await prisma.complaint.findUnique({
      where: { id: req.params.id },
      include: {
        messages: true
      }
    });

    if (!complaint) {
      return res.status(404).json({ message: 'Complaint not found' });
    }

    if (complaint.userId !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to view this complaint' });
    }

    res.json(complaint);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching complaint' });
  }
});

router.post('/:id/messages', authenticateToken, async (req, res) => {
  try {
    const { content } = z.object({ content: z.string().min(1) }).parse(req.body);
    
    const complaint = await prisma.complaint.findUnique({
      where: { id: req.params.id }
    });

    if (!complaint) {
      return res.status(404).json({ message: 'Complaint not found' });
    }

    if (complaint.userId !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to add messages to this complaint' });
    }

    const message = await prisma.message.create({
      data: {
        content,
        complaintId: req.params.id
      }
    });

    res.status(201).json(message);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error adding message' });
  }
});

module.exports = router; 