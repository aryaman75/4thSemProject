const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

router.post("/register" , async  (req , res)=>{
   let userInDb = await User.findOne({username : req.body.username})
   if(userInDb){
    return res.status(400).json("User with this user name already exists")
   } 
    try{
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password , salt)
        const newUser = await new User({
            username : req.body.username,
            email : req.body.email,
            password : hashedPassword,
            isAdmin : req.body.isAdmin,
        })
        const userCreated = await newUser.save()
        res.status(200).json(userCreated)
    }catch(err){
        res.status(400).json(err)
    }
})


router.post("/login" , async (req , res) =>{
  try{
      const user = await User.findOne({username:req.body.username})
      !user && res.status(400).json("User Not Found")
      const passwordCompare = await bcrypt.compare(req.body.password , user.password)
      if(!passwordCompare){
          return res.status(400).json("Invalid Credentails")
      }
      const accessToken = jwt.sign({
          id:user._id,
          isAdmin:user.isAdmin
        },
        process.env.JWT_SEC,
        {expiresIn:"3d"}
      )
        const {password , ...other} = user;
        res.status(200).json({message : "User Logged In Succesfully" , data : other , accessToken})
  }catch(err){
    res.status(501).json(err)
  }
})
module.exports = router;