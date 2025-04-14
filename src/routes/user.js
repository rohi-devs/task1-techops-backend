const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');

const prisma = new PrismaClient();


const updateProfileSchema = z.object({
  name: z.string().min(2).max(50).optional()
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

router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true
      }
    });

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile' });
  }
});


router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { name } = updateProfileSchema.parse(req.body);

    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: { name },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true
      }
    });

    res.json(updatedUser);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error updating profile' });
  }
});
router.delete('/profile', authenticateToken, async (req, res) => {
  try {
    await prisma.user.delete({
      where: { id: req.user.id }
    });

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Error deleting profile' });
  }
});

router.get('/summary', authenticateToken, async (req, res) => {
  try {
    const complaints = await prisma.complaint.groupBy({
      by: ['status'],
      where: { userId: req.user.id },
      _count: true
    });

    const summary = {
      total: complaints.reduce((acc, curr) => acc + curr._count, 0),
      pending: complaints.find(c => c.status === 'PENDING')?._count || 0,
      inProgress: complaints.find(c => c.status === 'IN_PROGRESS')?._count || 0,
      resolved: complaints.find(c => c.status === 'RESOLVED')?._count || 0
    };

    res.json(summary);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching summary' });
  }
});

module.exports = router; 