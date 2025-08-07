import jwt from "jsonwebtoken";

const userAuth=async(req,res,next)=>{
    const {token}=req.cookies;

    if(!token){
        return res.json({suceess:false,message:'Authorize Again'});
    }
    try{
        const tokenDecode=jwt.verify(token,process.env.JWT_SECRET);
        if(tokenDecode.id){
            req.body.userId=tokenDecode.id;
        }
        else{
            return res.json({success:false,message:'Authorize Again'});
        }
        next();

    }catch(error){
        return res.json({success:false,message:error.message});
    }

}

export default userAuth;