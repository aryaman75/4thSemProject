const jwt = require("jsonwebtoken")
const verifyToken = (req, res , next) =>{
    const authToken = req.headers.accesstoken
    if(!authToken){
        return res.status(400).json("Not authenticated")
    }
    jwt.verify(authToken, process.env.JWT_SEC , (err , user)=>{
        if(err){
            return res.status(403).json("Token is not valid")
        }
        req.user = user
        next()
    })
}

const verifyTokenAndAuthorization  = (req , res , next) =>{
    verifyToken(req , res , ()=>{
        if(req.user.id === req.params.id || req.user.isAdmin){
            next()
        }else{
            return res.status(403).json("Your are not allowed to do that")
        }
    })
}


const verifyTokenAndAdmin  = (req , res , next) =>{
    verifyToken(req , res , ()=>{
        if(req.user.isAdmin){
            next()
        }else{
            return res.status(403).json("Only admin are  allowed to do that")
        }
    })
}
module.exports = {verifyToken ,verifyTokenAndAdmin , verifyTokenAndAuthorization }