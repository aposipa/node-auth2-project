const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const Users = require("../users/users-model");
const { jwtSecret } = require('../config/secrets.js');

router.post("/register", (req, res) => {
    let user = req.body; // username, password

    const rounds = process.env.HASH_ROUNDS || 8;

    const hash = bcrypt.hashSync(user.password, rounds);

    user.password = hash;

    Users.add(user)
    .then(user => {
        res.status(201).json(user);
    })
    .catch(err => {
        console.log(err);
        res.status(500).json({ message: "cannot register user", err });
    });
});

router.post('/login', (req, res) => {
    const { username, password, department } = req.body; 

    Users.findBy({ username })
    .then(([user]) => {
        if(user && bcrypt.compareSync(password, user.password)) {
            const token = generateToken(user);
            res.status(200).json({ message: "Welcome!", token });
        } else {
            res.status(401).json({ message: "you cannot enter here!" });
        }
    })
    .catch(err => {
        console.log(err);
        res.status(500).json({ message: "cannot login user", err });
    });
});

function generateToken(user) {
    const payload = {
        userId: user.id,
        username: user.username,
        department: user.department || 'user'
    };
    const options = {
        expiresIn: '1h',
    };
    return jwt.sign(payload, jwtSecret, options);
}

module.exports = router;