
require("dotenv").config();  // must be at top. Not used in this file currently.

const express = require("express");
const bodyParser = require("body-parser"); // to support URL-encoded bodies
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encryp = require("mongoose-encryption");
// const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const app = express();

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
//1) Setup session
app.use(session({
    secret: "mylittlesecret", // should be inside an environment variable
    resave: false,
    saveUninitialized: false,
}));

//2) Initialize 
app.use(passport.initialize());
app.use(passport.session());

// "userDB" is the name of the database
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

userSchema.plugin(passportLocalMongoose);

//Encryp using mongoose-encryp
// userSchema.plugin(encryp, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  res.set(
    'Cache-Control', 
    'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
);
    if(req.isAuthenticated()){
        res.render("secrets")
    }
    else{
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

app.post("/register", function (req, res) {
  User.register({username: req.body.username}, req.body.password, function(err, user){
      if(err){
        console.log(err);
        res.redirect("/register");
      }
      else{
          passport.authenticate("local")(req, res, function(){
              res.redirect("/secrets")
          });
      }
  })
});

// this is the original login route (with the bug):
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local", { failureRedirect: '/login' })(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

// this is the new login route, which authenticates first and THEN
// does the login (which is required to create the session, or so I 
// understood from the passport.js documentation). 
// A failed login (wrong password) will give the browser error 
// "unauthorized".
 
app.post("/login", passport.authenticate("local"), function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password     
    });
    req.login(user, function(err) {
        if(err) {
            console.log(err);
        } else {
            res.redirect("/secrets");
        }
    });
});
 

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
