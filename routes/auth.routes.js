const { Router } = require("express");
const router = new Router();
const mongoose = require("mongoose");
const User = require("../models/User.model");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

router.get("/signup", (req, res) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  //   console.log("The form:", req.body);

  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory.Please provide your username, email and password."
    });
    return;
  }
  // make sure passwords are strong:
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (!regex.test(password)) {
    res.status(500).render("auth/signup", {
      errorMessage:
        "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter."
    });
    return;
  }
  bcryptjs
    .genSalt(saltRounds)
    .then((salt) => bcryptjs.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        username,
        email,
        passwordHash: hashedPassword
      });
    })
    .then((userFromDB) => {
      //   console.log(`Newly created user is: `, userFromDB);
      res.redirect("/userProfile");
    })
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else {
        next(error);
      }
    });
});

router.get("/login", (req, res) => {
  res.render("auth/login");
});

router.post("/login", (req, res, next) => {
  const { email, password } = req.body;
  console.log("SESSION ======>", req.session);

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both email & password to login."
    });
    return;
  }

  User.findOne({ email })
    .then((user) => {
      if (!user) {
        console.log("Email not registered.");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password."
        });
        return;
      } else if (bcryptjs.compareSync(password, user.passwordHash)) {
        // res.render("users/user-profile", { user });
        req.session.currentUser = user;
        res.redirect("/userProfile");
      } else {
        console.log("Incorrect password.");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password."
        });
      }
    })
    .catch((error) => next(error));
});

router.post("/logout", (req, res, next) => {
  req.session.destroy((err) => {
    if (err) next(err);
    res.redirect("/");
  });
});

router.get("/userProfile", (req, res) => res.render("users/user-profile"));
module.exports = router;
