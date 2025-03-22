import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// Defining the User Schema
const userSchema = new Schema(
    {
        // Username field
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true, // for more efficient searching we can use index as true
        },
        // Email field
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        // Full name field
        fullName: {
            type: String,
            required: true,
            index: true,
            trim: true,
        },
        // Avatar field (Cloudinary URL)
        avatar: {
            type: String,
            required: true,
        },
        // Cover Image field (optional)
        coverImage: {
            type: String,
        },
        // Watch History field (array of video IDs)
        watchHistory: [
            {
                type: Schema.Types.ObjectId,
                ref: "Video",
            },
        ],
        // Password field (hashed)
        password: {
            type: String,
            required: [true, "Password is required"],
        },
        // Refresh token for authentication
        refreshToken: {
            type: String,  // ✅ Fixed typo (typr → type)
        },
    },
    { timestamps: true } // Automatically adds createdAt and updatedAt fields
);

// PASSWORD ENCRYPTION WORKS HERE
// Pre-save hook to hash password before saving to the database
userSchema.pre("save", async function (next) {
    // Only hash the password if it has been modified
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);  // ✅ Added "await"
    next();
});

// Method to check password correctness
userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password);
};

// Generate Access Token
userSchema.methods.generateAccessToken = function () {
    // jwt is bearer token — it acts like a key, giving access to the data
    return jwt.sign(  // ✅ Replaced "JsonWebToken" with "jwt"
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        }
    );
};

// Generate Refresh Token
userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(  // ✅ Replaced "JsonWebToken" with "jwt"
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        }
    );
};

// Exporting the User model
export const User = mongoose.model("User", userSchema);

// bcrypt: for password hashing — keeps passwords secure by encrypting them
// jwt: for generating access and refresh tokens — allows for secure user authentication
