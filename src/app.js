import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"

const app=express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials:true

}))
//integrating ecxpress with json directly and writing about limiting size
app.use(express.json({limit:"16kb"}))
//if data coming in the form of url then it is good practice extended is just for nested data it is optional
app.use(express.urlencoded({extended:true,limit:"16kb"}))
app.use(express.static("public"))
app.use(cookieParser())


//routes

import userRouter from './routes/user.routes.js'

//routes Declaration
app.use("/api/v1/users",userRouter)//this ensures when someone goes to users we give control to the userRouter 




export { app }