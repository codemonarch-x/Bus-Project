import express from "express";
import cors from "cors";
import connectDB from "./db/db.js";
import userRoutes from "./Rout/userRout.js";
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/api", userRoutes);

connectDB();

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
