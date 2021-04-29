require('dotenv').config()   // for .env

// requiring all the modules
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const ejs = require('ejs');
const session = require('express-session');
const nodemailer = require('nodemailer');
var bcrypt = require('bcrypt-nodejs');
const ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn

require('./models/users');

// for passportJS (for simplified authentication)
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
var LocalStrategy = require('passport-local').Strategy;

// app
const app = express();
app.use(bodyParser.urlencoded({extended: true}))
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public'));

//session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false,
}));
app.use(passport.initialize())
app.use(passport.session());

// mongoose connect
mongoose.connect('mongodb://localhost/'+ process.env.DBNAME, {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false});
mongoose.set('useCreateIndex', true) // to remove deprication error

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  if(user!=null){
    done(null,user);
  }
});


const User = mongoose.model('User');  // creating User model


app.get('/', (req, res)=>{
  res.render('home')
})

app.get('/login', (req, res)=>{
  res.render('login', {msg: '', seller: false})
})

app.get('/signup', (req, res)=>{
  res.render('signup', {msg:'', name:'', birthday: '', housenumber: '', street:'', city: '', state: '', state:'', country:'', pincode:'', email:'', seller: false})
})

app.get('/main', (req, res)=>{
  if(req.isAuthenticated()){
    if(!req.seller){
      res.render('main', {user: req.user})
    }else{
      res.redirect('logout')
    }
  }else{
    res.render('login', {msg: 'please login', seller: false})
  }
})

app.get('/forgot', (req, res)=>{
  res.render('forgot', {msg: '', seller: false})
})
let transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  service: 'gmail',
  auth:{
    user: process.env.EMAIL,
    pass: process.env.PASS
  }
})
app.post('/signup', (req, res)=>{
  const user = new User({
    name: req.body.name,
    birthday: req.body.birthday,
    address: {
      housenumber: req.body.housenumber,
      street: req.body.street,
      city: req.body.city,
      state: req.body.state,
      country: req.body.country,
      pincode: req.body.pincode
    },
    email: req.body.email
  })
  User.findOne({email: req.body.email}, (err, foundUser)=>{
    if(err){
      console.log(err)
    }
    else if(foundUser == null){
      let otp = Math.random();
      otp = otp * 1000000;
      otp = parseInt(otp);
      user.otp = otp;
      user.otpexpire = Date.now() + 3600000;

      user.save()
      var mailOptions = {
        to: req.body.email,
        subject: 'OTP for your registration',
        html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
      };

      transporter.sendMail(mailOptions, (err, info)=>{
        if(err){
          console.log(err)
        }else{
          res.render('verifyotp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email, seller: false})
        }
      })
    }else{
      res.render('signup', {name: req.body.name, email:'',birthday: req.body.birthday, housenumber: req.body.housenumber, street: req.body.street, city: req.body.city, state: req.body.state, country: req.body.country, pincode: req.body.pincode, msg: 'This email already exists please use different one', seller: false})
    }
  })
});


app.post('/verify', (req, res)=>{
  User.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
    if(err){
      console.log(err)
    }else{
      if(!foundUser){
        res.render('verifyotp', {email: req.body.email, msg: 'otp expired click resend otp', seller: false})
      }else{
        if(foundUser.otp == req.body.otp){
          res.render('createusername', {msg:'', email: req.body.email, seller: false})
        }else{
          res.render('verifyotp', {email: req.body.email, msg: 'incorrect otp', seller: false})
        }
      }
    }
  })
});

app.post('/resendotp', (req, res)=>{
  User.findOne({email: req.body.email}, function(err, foundUser){
    if(err){
      console.log(err)
    }else{
      var otp = Math.random();
      otp = otp * 1000000;
      otp = parseInt(otp);
      User.findOneAndUpdate({email: req.body.email}, {otp: otp, otpexpire: Date.now()+3600000}, function(err, done){
        if(err){
          console.log(err)
        }
      })
    }
    var mailOptions = {
      to: req.body.email,
      subject: 'OTP for your registration',
      html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
    };

    transporter.sendMail(mailOptions, (err, info)=>{
      if(err){
        console.log(err)
      }else{
        res.render('verifyotp', {msg:'otp sent again to '+ req.body.email, email: req.body.email, seller: false})
      }
    })
  })

});

app.post('/createUser', (req, res)=>{
  User.findOne({username: req.body.username}, (err, foundUser)=>{
    if(err){
      console.log(err)
    }
    else if(foundUser == null){
      if(req.body.password == req.body.confirmPassword){
        User.findOne({email: req.body.email}, function(err, foundUser){
          if(err){
            console.log(err)
          }else{
            foundUser.username = req.body.username;
            foundUser.password = req.body.password;
            foundUser.save(function(err){
              req.logIn(foundUser, function(err){
                if(!err){
                  res.redirect('/main')
                }
              })
            })
          }
        })
      }else{
        res.render('createusername', {msg: "passwwords didn't match", email: req.body.email, seller: false})
      }
    }else{
      res.render('createusername', {msg: 'username already exists try another one', email: req.body.email, seller: false})
    }
  })
})

// passport.use(new LocalStrategy(function(username, password, done) {
//     User.findOne({ username: username }, function(err, user) {
//       console.log(arguments);
//       if (err) {
//         return done(err);
//       }
//       if (!user) {
//         return done(null, false, { message: 'Incorrect username.' });
//       }
//       if (!user.validPassword(password)) {
//         return done(null, false, { message: 'Incorrect password.' });
//       }
//       return done(null, user);
//     });
//   }
// ));
// app.post('/login',
//   passport.authenticate('local', {
//     successRedirect: '/main',
//     failureRedirect: '/login',
//     failureFlash: true
//   })
// );
// passport.use("login", new LocalStrategy(function(username, password, done){
//   User.findOne({username : username}, function(err, user){
//     if(err){return done(err)}
//     if(!user){
//         return done(null, false, {messages : "no such user exist" })
//     }
//     if(user.password != password){
//         return done(null, false, {messages : "invalid password please try again"})
//     }else{
//         return done(null , user);
//     }
//   })
// }))

passport.use('user-local', new LocalStrategy(function(username, password, done){
  User.findOne({ username: username }, function(err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

app.post("/login", function(req, res, next){
    passport.authenticate("user-local", function(err, user, info){
        if(err){ return next(err);}
        if(!user){return res.render("login", {msg : info.message, seller: false})}
        req.logIn(user, function(err){
            if(err){ return next(err); }
            return res.redirect("/main");
        })
    })(req, res, next)
});



app.post('/forgot', (req, res)=>{
  User.findOne({email: req.body.email}, (err, foundUser)=>{
    if(err){
      console.log(err)
    }else if(foundUser == null){
      res.render('forgot', {msg: 'No account exists with that email, please enter valid email', seller: false})
    }else{
      var otp = Math.random();
      otp = otp * 1000000;
      otp = parseInt(otp);
      User.findOneAndUpdate({email: req.body.email}, {otp: otp, otpexpire: Date.now()+3600000}, (err, done)=>{
        if(err){
          console.log(err)
        }
      })
      var mailOptions = {
        to: req.body.email,
        subject: 'OTP for your password change',
        html: '<h3>Your username is </h3>'+ '<h1>'+ foundUser.username +'</h1>' +'<h3> And OTP for password change is </h3>' + '<h1>'+ otp +'</h1>'
      };
      transporter.sendMail(mailOptions, (err, info)=>{
        if(err){
          console.log(err)
        }else{
          res.render('passwordchange', {username: foundUser.username, msg:'', email:req.body.email, seller: false})
        }
      })
    }
  })
});

// passport.use('passwordchange', new LocalStrategy(function(username, otp, password, confirmpassword, done){
//   if(otp == this.otp){
//     User.findOne({username: username}, function(err, user){
//       if(err){return done(err)}
//       else{user.password = password}
//     })
//   }else{
//     res.render('passwordchange', {msg: 'incorret otp', username:''})
//   }
//
// }))

app.post('/passwordchange', (req, res)=>{
  User.findOne({username: req.body.username}, function(err, foundUser){
    if(err){
      console.log(err)
    }else if(foundUser == null){
      res.render('passwordchange', {username: req.body.username, msg: 'otp expired click resend', email: req.body.email, seller: false})
    }
    else{
      if(foundUser.otp == req.body.otp){
        if(req.body.password == req.body.confirmPassword){
          User.findOne({username: req.body.username}, function(err, foundUser){
            if(err){
              console.log(err)
            }else{
              foundUser.password = req.body.password
              foundUser.save(function(err){
                if(err){
                  console.log(err)
                }else{
                  res.redirect('/main')
                }
              })
            }
          })
        }else{
          res.render('passwordchange', {username: req.body.username, msg: "password didn't match", email: req.body.email, seller: false})
        }
      }else{
    res.render('passwordchange', {username: req.body.username, msg: 'incorrect otp', email: req.body.email, seller: false})
  }
}
})
})

app.post('/resendotpforpasswordchange', (req, res)=>{
  var otp = Math.random()
  otp = otp * 1000000
  otp = parseInt(otp)

  User.findOneAndUpdate({username: req.body.username}, {otp: otp, otpexpire: Date.now()+3600000}, (err, done)=>{
    if(err){
      console.log(err)
    }
  })
  var mailOptions = {
    to: req.body.email,
    subject: 'OTP for your password change',
    html: '<h3>Your username is <h3>'+ '<h1>' + req.body.username + '</h1>' + '<h3> And otp for password change is </h3>' + '<h1>' + otp + '</h1>'
  };

  transporter.sendMail(mailOptions, (err, info)=>{
    if(err){
      console.log(err)
    }else{
      res.render('passwordchange', {username: req.body.username, msg:'otp sent again to '+ req.body.email, email: req.body.email, seller: false})
    }
  })
})


app.get('/logout', (req, res)=>{
  req.logout();
  res.redirect('/');
});

const port = process.env.PORT || 3000
app.listen(port, ()=>{

  console.log('server started on port ' + port)
})
