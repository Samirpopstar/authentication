const express = require('express');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

// const md5 = require("md5"); 
// md5 helps to convert your password into hash and bcrypt helps to further extend the hash.

const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')


const app = express();

// To create cookies and sessions you need to write the code above mongoose.connect() //

app.use(session({
    secret:"bhandinah",
    resave:false,
    saveUninitialized:false
}))

app.use(passport.initialize());
app.use(passport.session());

// Below Here mongoose.connect


mongoose.set("useCreateIndex", true);

app.set("view engine", "ejs")
app.set('trust proxy', true)

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('public'));

const userSchema = new mongoose.Schema({
    email: String, 
    password: String,
    googleId: String,
    googleEmail: String,
    Name: String,
    secret: String,
    ip:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    
    // Below here client id and client secret.
    
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileUrL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id , googleEmail: profile.emails[0].value , Name:profile.displayName}, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
    const userIp = req.ip;
    User.findOne({ip:null}, function(err, foundIp) {
        if (err) {
            console.log(err)
        }else {
            if (foundIp) {
                foundIp.ip = userIp;
                foundIp.save();
            }
        }
    })
    res.render("home")
})

app.get("/auth/google",
    passport.authenticate("google", { scope: ['profile', 'email'] })
)

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


app.get("/register", function (req, res) {
    res.render("register")
})

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
    User.find({"secret": {$ne: null}}, function (err, foundUsers) {
            if (err) {
                console.log(err)
            }else {
              if (foundUsers) {
           res.render("secrets",
         {usersWithSecrets: foundUsers})
                }
            }
        })
    }else {
        res.redirect("/login")
    }
})

app.get("/submit", function 
(req, res) {
     if (req.isAuthenticated()) {
        res.render("submit")
    }else {
        res.redirect("/login")
    }
})

app.get("/logout", function (req,res) {
    req.logout();
    res.redirect("/")
})


app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register")
        }else{
            passport.authenticate("local")(req, res, function () {
                res.redirect("login")
            })
        }
    })
})

app.get("/login", function (req,res) {
    res.render("login")
})

app.post("/login", function(req, res) {
    const user = new User({
        username:req.body.username,
        password: req.body.password
    })
    
    req.login(user, function (err) {
        if (err) {
            console.log(err);
        }else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            })
        }
    })
})

app.post("/submit", function (req,res) {
    const submittedSecret = req.body.secret;
    
    User.findById(req.user.id, function(err, foundUser) {
        if (err) {
            console.log(err)
        }else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets")
                })
            }
        }
    })
})

app.listen(3000, function() {
    
  console.log("node server running");
})
