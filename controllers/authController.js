 import bcrypt from "bcryptjs";
import createHttpError from "http-errors";
import { generateToken, verifyToken } from "../services/JwtService.js";
import { validationResult } from "express-validator";
import transporter from "../config/nodemailer.js";
import userModel from "../models/userModel.js";


const registerController = async (req, res, next) => {
    try {
        // validation for on req.body by express-validator
        // error in register-validator.js file
        // middleware applied registerValidator on register route
        const result = validationResult(req);
        // agar result.isEmpty nahi hai....error hai..to first error send karo 
        if (!result.isEmpty()) {
            throw createHttpError(400, result.array()[0].msg);
        }
        // destructure all input values from req.body....
        const { firstName, lastName, email, password, role } = req.body;
        
        // userModel is mongoose model or model used for  any operation in db.
        // findOne is also mongoose syntax used for finding any matching document 
        const userExist = await userModel.findOne({ email });
        // if (userExist) return res.status(409).json({ message: "Email Already Exist" })
        // http-errors library to create errors....
        // if userExist create error and it will not execute next code...it will break
        if (userExist) throw createHttpError(409, "Email Already Exist")
        
         // we will not safe original password in db 
        //  used bcrypt library to hashed Password 
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // generate otp for email verification
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        // console.log(otp, "OTP");

        // create expire time for otp.... 24h
        const expiredAt = Date.now() + 24 * 60 * 60 * 1000;
        // console.log(expiredAt, "expire");

     
        // Choose a random background color from the array
       const backgroundColors = [
        "e57f7f",
        "69a69d",
        "7a9461",
        "98b8e1",
        "e0d084",
        "516087",
        "ab9f8e",
        "c150ad",
        "be94eb",
        "a6a7ae",
        ];

       // define an array of background colors for avatar
        // Define an array of background colors
    const randomBackgroundColor =
      backgroundColors[Math.floor(Math.random() * backgroundColors.length)];

        await userModel.create({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            role,
            verifyOtp: otp,
            verifyOtpExpiredAt: expiredAt
        });

 
        // for sending email we use nodemailler library
        // already define tranporter
        await transporter.sendMail({
            from: "sumairapathan400@gmail.com",
            to: email, // list of receivers
            subject: "Email Verification", // Subject line
            text: `Your OTP is${otp}.verify Your account using this otp.`, // plain text body
        });
        // sending response
        res.status(201).json({ message: "Enter OTP sent on your Email" })


    } catch (error) {
        // res.status(500).json({ message: "internal server error", error: error.message })
        // we have define global error handler....app.use(globalErrorHandler)
        next(error)
    }
}

const loginController = async (req, res, next) => {
    try {
         // validation for on req.body by express-validator
        // error in  login-validator.js file
        // middleware applied loginValidator on login route
        const result = validationResult(req);
        if (!result.isEmpty()) {
            throw createHttpError(400, result.array()[0].msg);
        }
        const { email, password } = req.body;
        const user = await  userModel.findOne({ email })
        if (!user) throw createHttpError(401, "Invalid email or password")

        //  user.password is hashed PW saved in db
        // password is from req.body
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) throw createHttpError(401, "Invalid email or password")

            

        // token generate karne ka code hai
        // ye hamara payload hai....user data ka data token may save karenge
        const userData = {
            userId: user._id,
            role: user.role
        }
        const token = generateToken(userData);

        //    const decode= verifyToken(token);
        //    console.log(decode)


        res.json({ token })


    } catch (error) {
        next(error)
    }
}

const verifyEmailController = async (req, res, next) => {
    try {
        const { email, verifyOtp } = req.body;
        if (!email || !verifyOtp) throw createHttpError(401, "Email and OTP are required")
            // In user we get all information of user from database if user exist.... if user is not exist we get errors
        const user = await userModel.findOne({ email });
        console.log(user, "user")
        if (!user) throw createHttpError(404, "User Not Found");
 
        //  console.log( user.verifyOtp,"db otp");
        //  console.log( verifyOtp,"req body otp");
        
        // user.verifyOtp from db and verifyOtp from req.body
        // OTP saved in db not equal to req.body otp or db otp is empty 
        if (user.verifyOtp !== verifyOtp || user.verifyOtp === '') {
            throw createHttpError(401, "Invalid OTP")
        }

        // Current time greater then expire time that means OTP expire  
        if (user.verifyOtpExpiredAt < Date.now()) {
            // if otp expired...delete user data from db 
            await userModel.findByIdAndDelete(user._id);
            throw createHttpError(400, "OTP  Expired.Register Again");
        }
        // update user data 
        user.isVerified = true;
        user.verifyOtp = "";
        user.verifyOtpExpiredAt = 0;
        // save() mongoose syntax used for saving user information
        await user.save();
        res.json({ message: "Email Verified Successfully." })
    } catch (error) {
        next(error)
    }
}

const profileController = async (req, res, next) => {
    const id = req.user._id;
    // console.log(id,"coming from token..from isAuthenticated")
    try {
        const userId = req.params.id
        //    console.log(userId,"user id")
        if (id !== userId) throw createHttpError(401, "Unauthorized")
        const user = await userModel.findById({ _id: userId }).select(" -password -__v -createdAt -updatedAt")
        res.json(user)
    } catch (error) {
        next(error)
    }
}

const protectedController = (req, res, next) => {
    res.json({ message: "You can access it." })
}

const otpResetPasswordController = async (req, res, next) => {
    try {
        const { email } = req.body;
        if (!email) throw createHttpError(401, "Email required")
        const user = await userModel.findOne({ email });
        if (!user) throw createHttpError(404, "User Not Found");

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        // console.log(otp, "OTP");

        const expiredAt = Date.now() + 1 * 60 * 1000;
        // console.log(expiredAt, "expire");

        await transporter.sendMail({
            from: "sumairapathan400@gmail.com",
            to: email, // list of receivers
            subject: "OTP for Reset password", // Subject line
            text: `Your OTP is${otp}.To reset Password use this OTP.`, // plain text body
        });

        user.resetOtp = otp;
        user.resetOtpExpiredAt = expiredAt;
        await user.save();

        res.status(201).json({ message: "Enter OTP sent on your Email" })
    } catch (error) {
        next(error)
    }
}

const resetPasswordController = async (req, res, next) => {
    try {
        const { email, resetOtp, password } = req.body;
        if (!email || !resetOtp || !password) throw createHttpError(400, "Email and OTP are required")
        const user = await userModel.findOne({ email });

        if (!user) throw createHttpError(404, "User Not Found");

        if (user.verifyOtp !== resetOtp || user.resetOtp === '') {
            throw createHttpError(401, "Invalid OTP")
        }
        if (user.verifyOtpExpiredAt < Date.now()) {
            throw createHttpError(401, "OTP  Expired");
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user.password = hashedPassword;
        user.resetOtp = "";
        user.resetOtpExpiredAt = 0;

        await user.save();
        res.json({ message: "Password Reset Successfully." })
    } catch (error) {
        next(error)
    }
}

export { registerController, loginController, profileController, protectedController, verifyEmailController, otpResetPasswordController, resetPasswordController }