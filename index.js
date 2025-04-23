require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const { PrismaClient } = require("@prisma/client");
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const cookieParser = require("cookie-parser");
const prisma = new PrismaClient();
const app = express();

// app.use(cors());
const allowedOrigins = [
  "http://localhost:5173",
  "https://task1-techops-frontend.vercel.app",
  "https://task1-techops-frontend-git-main-vishs-projects-b03efeba.vercel.app",
  "https://task1-techops-frontend-vishs-projects-b03efeba.vercel.app",
  "https://fend.rohidevs.engineer",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Admin API Documentation",
      version: "1.0.0",
      description: "API documentation for the admin routes",
    },
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  apis: ["./src/routes/*.js"], // path to your API routes
};

const specs = swaggerJsdoc(options);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));

app.get("/", (req, res) => {
  console.log("Reached CTF complaint handler backend");
  res.send("Complaint handler route accessed");
});

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
