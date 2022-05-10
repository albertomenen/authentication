//jshint esversion:6

require('dotenv').config()



const express = require ("express");
const bodyParser = require ("body-parser");
const ejs = require ("ejs");
const mongoose = require ("mongoose")
const md5 = require ("md5");
const saltRounds = 10;
var bcrypt = require('bcryptjs');
const session = require('express-session');
const passport = require ("passport");
const passportLocalMongoose = require ("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require ("mongoose-findorcreate");
const FacebookStrategy = require ("passport-facebook").Strategy;



const app = express();



app.use(session({
  secret: "our little secret",
  resave: false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true});


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleID: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



const User = new mongoose.model ("User", userSchema);

passport.use(User.createStrategy());


passport.serializeUser(function(user, done, id) {
  done(null, user.id);
});


passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FACEBOOK,
    clientSecret: process.env.CLIENT_SECRET_FACEBOOK,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.use(express.static("public"));
app.set("view engine", "ejs");
app.use (bodyParser.urlencoded({
  extended:true
}));




app.get ("/", function (req, res) {
  res.render("home");
});

app.get('/auth/google',
        passport.authenticate('google', {scope: ['profile', 'email']})
    );

    app.get('/auth/google/callback',
        passport.authenticate('google', {
            successRedirect: '/profile',
            failureRedirect: '/fail'
        })
    );

    app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get ("/login", function (req, res) {
  res.render("login");
});

app.get ("/register", function (req, res) {
  res.render("register");
});

app.get("/submit", function (req,res) {
  if (req.isAuthenticated()){
    res.render("secrets");
  }else {
    res.redirect("/login");
  }
});

// Para que se suban las publicaciones que ponemos

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()){
    res.render("submit");
  }else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect ("/");
});


app.post ("/register", function(req, res) {

  User.register({username: req.body.username}, req.body.password, function(err, user){
  if (err){
    console.log(err);
    res.redirect("/register");
  } else
  passport.authenticate("local") (req, res, function(){
    res.redirect("/secrets");
  });
});
});





app.post("/login", function(req,res){

const user = new User ({
    username: req.body.username,
    password: req.body.password
});

req.login(user, function(err){
  if(err) {
    console.log(err);
  }else {
    passport.authenticated("local")(req,res, function() {
      res.redirect("/secrets");
    });
  }
});

});


app.listen(3000, function() {
  console.log("Server started on port 3000")
});
