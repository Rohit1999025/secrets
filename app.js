require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/UserDB", { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("Successfully connected to MongoDB"))
    .catch(err => console.error("Error connecting to MongoDB:", err));

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        password: user.password
      });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

const clientID = process.env.CLIENT_ID;
const clientSecret = process.env.CLIENT_SECRET;

if (!clientID || !clientSecret) {
    throw new Error('Google OAuth clientID and clientSecret must be set in .env file');
}

passport.use(new GoogleStrategy({
    clientID: clientID,
    clientSecret: clientSecret,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  async function(accessToken, refreshToken, profile, cb) {
    try {
      console.log("Profile:", profile);
      const user = await User.findOrCreate({ googleId: profile.id });
      return cb(null, user);
    } catch (err) {
      console.error("Error in findOrCreate:", err);
      return cb(err, null);
    }
  }
));

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", async function(req, res) {
    if (req.isAuthenticated()) {
        try {
            const foundUsers = await User.find({ "secret": { $ne: null } });
            res.render("secrets", { usersWithSecrets: foundUsers });
        } catch (err) {
            console.log(err);
            res.send("Error finding secrets");
        }
    } else {
        res.redirect("/login");
    }
});

app.get("/submit" , function(req,res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", async function(req,res){
    const submittedSecret = req.body.secret;

    try {
        const foundUser = await User.findById(req.user.id);
        if (foundUser) {
            foundUser.secret = submittedSecret;
            await foundUser.save();
            res.redirect("/secrets");
        } else {
            res.status(404).send("User not found");
        }
    } catch (err) {
        console.log(err);
        res.status(500).send("Error submitting secret");
    }
});

app.get("/logout", function(req, res, next) {
    req.logout(function(err) {
        if (err) {
            console.log(err);
            return next(err);
        }
        res.redirect("/");
    });
});

app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke! ' + err.message);
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
});
