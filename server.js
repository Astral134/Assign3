const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const jwt = require("jsonwebtoken");
const userService = require("./user-service");

dotenv.config();

const app = express();
const HTTP_PORT = process.env.PORT || 8080;

const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;

// Passport JWT Strategy setup
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

// ─── Routes ───────────────────────────────────────────────────────────────────

// Register a new user
app.post("/api/user/register", (req, res) => {
  userService
    .registerUser(req.body)
    .then((msg) => res.json({ message: msg }))
    .catch((msg) => res.status(422).json({ message: msg }));
});

// Login — returns a signed JWT
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

// Get favourites — protected
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

// Add to favourites — protected
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

// Remove from favourites — protected
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

// Connect to MongoDB once on cold start
userService.connect().catch((err) => {
  console.log(`Unable to connect to MongoDB: ${err}`);
});

// ─── Export for Vercel (no app.listen) ────────────────────────────────────────
module.exports = app;