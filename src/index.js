const jwt = require('jsonwebtoken');
class Auth {
  constructor(secretKey){
      this.secretKey = secretKey;
  }
  async verify(token){
      return new Promise((resolve,reject)=>{
         jwt.verify(token,this.secretKey,function (err,decoded){
              if(err != null){
                  return reject(err);
              }
              return resolve(createUser(decoded));
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
module.exports = Auth;

function createUser(o){
  if(o == null) throw new Error('user is not defined');
    let {type,data} = o;
    return {
        info:data,
        type,
        isCustomer(){
          return type === 'customer';
        },
        isPersonnel(){
          return type === 'personnel';
        }
    }
}

module.exports.jwt = function ({secret}){
  return function (req,res,next){
    if(req.method === 'OPTIONS'){
      next();
      return;
    }
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        if(token == null){
          res.sendStatus(401);
          return;
        }
        new Auth(secret).verify(token)
        .then((user)=>{
          req.user = user;
          next();
        }).catch(()=>{
           res.sendStatus(403);
        })
    } else {
        res.sendStatus(401);
    }
  }
}
