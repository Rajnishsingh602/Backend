import {v2 as cloudinary} from "cloudinary"
import { log } from "console";
import fs from "fs"




    // Configuration
    cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
        api_key: process.env.CLOUDINARY_API_KEY, 
        api_secret:process.env.CLOUDINARY_API_SECRET
    });

    const uploadOnCloudinary = async (localFilePath) => {
        try {
          if (!localFilePath) return null;
      
          // Upload file to Cloudinary
          const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto",
          });
      
          // File uploaded successfully
          console.log("File uploaded successfully", response.url);
      
          // Clean up: Remove local file after upload
          if (fs.existsSync(localFilePath)) {
            fs.unlinkSync(localFilePath);
            console.log("Local file deleted successfully");
          }
      
          return response;
        } catch (error) {
          // If upload fails, clean up temp file (if exists)
          if (fs.existsSync(localFilePath)) {
            fs.unlinkSync(localFilePath);
            console.log("Local file deleted due to upload failure");
          }
          console.error("Error uploading file:", error.message);
          return null;
        }
      };
      
      export { uploadOnCloudinary };
      