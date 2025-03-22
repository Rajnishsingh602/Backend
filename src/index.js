//require('dotenv').config({path: 
   //  './env'})
// Load environment variables at the top
console.log("Server starting...");
import userRoutes from "./routes/user.routes.js";



import dotenv from "dotenv";
dotenv.config({ path: './.env' });

import express from "express";
import connectDB from "./db/index.js";

// Initialize Express app
const app = express();
app.use(express.json());


app.use("/api/v1/users", userRoutes);//these are modifications from chatgpt because it has not been added there 

// Basic route to test server
app.get("/", (req, res) => {
  res.send("Hello world");
});

// Connect to MongoDB and start server only if connection succeeds
const startServer = async () => {
  try {
    await connectDB();
    console.log("DB Connection Successful");

    // Start the server only after DB connection is successful
    app.listen(process.env.PORT, () => {
      console.log(`App is listening on port ${process.env.PORT}`);
    });

  } catch (err) {
    console.error("DB Connection Failed:", err);
  }
};

startServer();











/*
2ND APPROACH TO DO THE SAME PROBLEM
import express from "express"
const app=express()

(async ()=>{
    try{
await mongoose.connect(`${process.env.MONGODB_URI}/ ${DB_NAME}`)
app.on("error",(error)=>{
    console.log("ERRR:",error);
    throw error;
    

})

app.listen(process.env.PORT,()=>{
    console.log(`App is listening on port $ {process.env.PORT}`);
    
})
    }
    catch(error){
        console.error("ERROR: ", error)
        throw err
    }
})()*/