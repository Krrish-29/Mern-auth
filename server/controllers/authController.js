import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const register = async (req,res)=>{
    
    const {name,email,password}=req.body;
    
    if(!name||!email||!password){
        return res.json({success:false,message:'Missing Details'});
    }

    try{

        const existingUser=await userModel.findOne({email});
        if(existingUser){
            return res.json({success:false,message:"Invalid Details"});
        }
        const hashedPassword=await bcrypt.hash(password,10);

        const user=new userModel({name,email,password:hashedPassword});
        await user.save();

        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV=='production'?'none':'strict',
            maxAge: 7*24*60*60*1000
        })

        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:'welcome',
            text:`Welcome`
        }
        await transporter.sendMail(mailOptions);

        return res.json({success:true});

    }catch(error){
        return res.json({success:false,message:error.message})
    }

}


export const login=async(req,res)=>{
    const {email,password}=req.body;

    if(!email||!password){
        return res.json({success:false,message:'Invalid Details'});
    }
    try{

        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'Invalid Details'});
        }
        
        const isMatch =await bcrypt.compare(password,user.password);
        if(!isMatch){
            return res.json({success:false,message:'Invalid Password'});
        }

        const token=jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV=='production'?'none':'strict',
            maxAge: 7*24*60*60*1000
        })
        return res.json({success:true});


    }catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const logout=async(req,res)=>{
    try{
        res.clearCookie('token',{
            httpOnly:true,
            secure:process.env.NODE_ENV==='production',
            sameSite:process.env.NODE_ENV=='production'?'none':'strict'
        })
        return res.json({success:true,message:'Logged Out'});
    }catch(error){
        return res.json({success:false,message:error.message});
    }
}


export const sendVerifyOtp = async(req,res)=>{
    try{
        
        const {userId}=req.body;
        
        const user=await userModel.findById(userId);
        if(user.isAccountVerified){
            return res.json({success:true,message:'Account already verified'});
        }
        const otp=String(Math.floor(100000+Math.random()*90000));
        user.verifyOtp=otp;
        user.verfiyOtpExpireAt=Date.now()+24*60*60*1000;
        await user.save();

        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Otp',
            text:`Otp: ${otp}`
        }
        await transporter.sendMail(mailOptions);

        return res.json({success:true,message:'Otp Send!'});


    }catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const verifyEmail = async (req,res)=>{
    const {userId,otp}=req.body;

    if(!userId||!otp){
        return res.json({success:false,message:'Invaild Details'});
    }
    try{
        const user=await userModel.findById(userId);
        if(!user){
            return res.json({success:false,message:'Invalid Details'});
        }
        if(user.verifyOtp===''||user.verifyOtp!==otp){
            return res.json({success:false,message:'Invalid Otp'});
        }
        if(user.verfiyOtpExpireAt<Date.now()){
            return res.json({success:false,message:'Otp Expired'});
        }
        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;
        await user.save();
        
        return res.json({success:true,message:'Email verified successfully'});

    }catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const isAuthenticated=async(req,res)=>{
    try{
        return res.json({success:true});
    }catch(error){
        res.json({success:false,message:error.message});
    }
}


export const sendResetOtp=async(req,res)=>{
    const {email}=req.body;
    if(!email){
        return res.json({success:false,message:"Invalid Details"});
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:"Invalid Details"});
        }
        const otp=String(Math.floor(100000+Math.random()*90000));
        user.resetOtp=otp;
        user.resetOtpExpireAt=Date.now()+15*60*1000;
        await user.save();

        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Otp',
            text:`Otp: ${otp}`
        }
        await transporter.sendMail(mailOptions);

        return res.json({success:true,message:'Otp Send!'});
    }catch(error){
        return res.json({success:false,message:error.message});
    }
}

export const resetPassword=async(req,res)=>{
    const {email,otp,newpassword}=req.body;
    if(!email||!otp||!newpassword){
        return res.json({success:false,message:'Invalid Details'})
    }
    try{
        const user=await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:'Invalid User'});
        }
        if(!user.resetOtp===''||user.resetOtp!==otp){
            return res.json({success:false,message:'Invalid Otp'});
        }
        if(user.resetOtpExpireAt<Date.now()){
            return res.json({success:false,message:'Otp Expired'});
        }
        const hashedPassword=await bcrypt.hash(newpassword,10);
        user.password=hashedPassword;
        user.resetOtp='';
        user.resetOtpExpireAt=0;

        await user.save(); 

        return res.json({success:true,message:"Password has been changed"});

    }catch(error){
        return res.json({success:false,message:error.message});
    }
}