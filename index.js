require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");

const cookieParser = require("cookie-parser");
const prisma = new PrismaClient();
const app = express();

// app.use(cors());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://task1-techops-frontend.vercel.app",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(morgan("dev"));
app.use(express.json());
app.use(cookieParser());
const authRoutes = require("./src/routes/auth.js");
const complaintRoutes = require("./src/routes/complaints");
const userRoutes = require("./src/routes/user");
const adminRoutes = require("./src/routes/admin");

app.use("/api/auth", authRoutes);
app.use("/api/complaints", complaintRoutes);
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
