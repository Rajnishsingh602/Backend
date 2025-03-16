import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

const uri = `${process.env.MONGODB_URI}/youtube`;

const connectDB = async () => {
  try {
    console.log("Attempting to connect to MongoDB...");
    const connection = await mongoose.connect(uri);
    console.log("Connected Successfully:", connection.connection.host);
  } catch (err) {
    console.error("Connection Failed:", err.message);
  }
};

connectDB();
