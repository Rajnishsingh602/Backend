import { ApiError } from "../../utils/ApiError.js";
import asyncHandler from "../../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";

// Middleware to verify JWT token
export const verifyJWT = asyncHandler(async (req, _, next) => { // underscore is same as response(res) it is written in industries
    try {
        // Extract access token from either cookies or Authorization header
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized request — No token provided");
        }

        // Verify the token
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        if (!decodedToken?._id) {
            throw new ApiError(401, "Invalid access token — No user ID in token");
        }

        // Find the user and attach to the request object
        const user = await User.findById(decodedToken._id).select("-password -refreshToken");
        if (!user) {
            throw new ApiError(401, "Invalid access token — User not found");
        }

        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token");
    }
});
