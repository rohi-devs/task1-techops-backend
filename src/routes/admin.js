const express = require('express');
const router = express.Router();
const { PrismaClient } = require('@prisma/client');
const { z } = require('zod');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const prisma = new PrismaClient();

const adminLoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6)
});

const createAdminSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2),
  password: z.string().min(6),
  role: z.enum(['MODERATOR', 'SUPER_ADMIN'])
});

const updateComplaintSchema = z.object({
  status: z.enum(['PENDING', 'IN_PROGRESS', 'RESOLVED']),
  response: z.string().optional()
});

const authenticateAdmin = async (req, res, next) => {
  console.log("req",req.headers);
  try {
    const token = req.headers.authorization?.split(' ')[1];
    console.log("token",token);
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("decoded",decoded);
    const admin = await prisma.user.findUnique({
      where: { id: decoded.id }
    });
    console.log(admin);

    if (!admin || (admin.role !== 'MODERATOR' && admin.role !== 'SUPER_ADMIN')) {
      return res.status(403).json({ message: 'Not authorized' });
    }

    req.admin = admin;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};


router.post('/login', async (req, res) => {
  try {
    const { email, password } = adminLoginSchema.parse(req.body);
    
    const admin = await prisma.user.findUnique({
      where: { email }
    });

    if (!admin || (admin.role !== 'MODERATOR' && admin.role !== 'SUPER_ADMIN')) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: admin.id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: admin.id,
        email: admin.email,
        name: admin.name,
        role: admin.role
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error logging in' });
  }
});

router.post('/create', authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ message: 'Only Super Admin can create new admins' });
    }

    const { email, name, password, role } = createAdminSchema.parse(req.body);
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newAdmin = await prisma.user.create({
      data: {
        email,
        name,
        password: hashedPassword,
        role
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true
      }
    });

    res.status(201).json(newAdmin);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error creating admin' });
  }
});


router.get('/complaints', authenticateAdmin, async (req, res) => {
  try {
    const complaints = await prisma.complaint.findMany({
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        },
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

router.put('/complaints/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status, response } = updateComplaintSchema.parse(req.body);
    
    const complaint = await prisma.complaint.update({
      where: { id: req.params.id },
      data: { status }
    });

    if (response) {
      await prisma.message.create({
        data: {
          content: response,
          complaintId: complaint.id
        }
      });
    }

    res.json(complaint);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: 'Validation error', errors: error.errors });
    }
    res.status(500).json({ message: 'Error updating complaint' });
  }
});

router.get('/statistics', authenticateAdmin, async (req, res) => {
  try {
    const totalComplaints = await prisma.complaint.count();
    const complaintsByStatus = await prisma.complaint.groupBy({
      by: ['status'],
      _count: true
    });
    const complaintsByCategory = await prisma.complaint.groupBy({
      by: ['category'],
      _count: true
    });

    res.json({
      total: totalComplaints,
      byStatus: complaintsByStatus,
      byCategory: complaintsByCategory
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching statistics' });
  }
});


router.get('/admins', authenticateAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ message: 'Only Super Admin can view all admins' });
    }

    const admins = await prisma.user.findMany({
      where: {
        role: {
          in: ['MODERATOR', 'SUPER_ADMIN']
        }
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true
      }
    });

    res.json(admins);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching admins' });
  }
});

module.exports = router; 