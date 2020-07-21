const jwt = require('jsonwebtoken');
module.exports = class Auth {
    constructor(secretKey){
        this.secretKey = secretKey;
    }
    async verify(token){
        return new Promise((resolve,reject)=>{
           jwt.verify(token,this.secretKey,function (err,decoded){
                if(err != null){
                    return reject(err);
                }
                return resolve(decoded);
            })
        })
      
    }
    async createToken({type,data}){
        return new Promise((resolve,reject)=>{
           jwt.sign({
            type,
            data
          },this.secretKey,{
             expiresIn:'1d',
           },function (err,encoded){
             if(err != null){
               return reject(err);
             }
             resolve(encoded);
           })
        });
     }
}
