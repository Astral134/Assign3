const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const jwt = require("jsonwebtoken");
const userService = require("./user-service");

dotenv.config();

const app = express();

const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("jwt"),
  secretOrKey: process.env.JWT_SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, (jwt_payload, next) => {
    if (jwt_payload) {
      next(null, {
        _id: jwt_payload._id,
        userName: jwt_payload.userName,
      });
    } else {
      next(null, false);
    }
  })
);

app.use(express.json());
app.use(cors());
app.use(passport.initialize());

// Middleware to ensure DB is connected before handling any request
app.use((req, res, next) => {
  userService
    .connect()
    .then(() => next())
    .catch((err) => {
      console.error("MongoDB connection error:", err);
      res.status(500).json({ message: "Database connection failed" });
    });
});

// ─── Routes ───────────────────────────────────────────────────────────────────

app.post("/api/user/register", (req, res) => {
  userService
    .registerUser(req.body)
    .then((msg) => res.json({ message: msg }))
    .catch((msg) => res.status(422).json({ message: msg }));
});

app.post("/api/user/login", (req, res) => {
  userService
    .checkUser(req.body)
    .then((user) => {
      const payload = {
        _id: user._id,
        userName: user.userName,
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET);
      res.json({ message: "login successful", token: token });
    })
    .catch((msg) => {
      res.status(422).json({ message: msg });
    });
});

app.get(
  "/api/user/favourites",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .getFavourites(req.user._id)
      .then((data) => res.json(data))
      .catch((msg) => res.status(422).json({ error: msg }));
  }
);

app.put(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .addFavourite(req.user._id, req.params.id)
      .then((data) => res.json(data))
      .catch((msg) => res.status(422).json({ error: msg }));
  }
);

app.delete(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .removeFavourite(req.user._id, req.params.id)
      .then((data) => res.json(data))
      .catch((msg) => res.status(422).json({ error: msg }));
  }
);

module.exports = app;