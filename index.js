const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors')
app.use(express.json());
app.use(cors());


let refreshTokens = [];
const users = [
    {
        id: "1",
        username: "john",
        password: "John0998",
        isAdmin: true
    },


    {
        id: "2",
        username: "jane",
        password: "jane0998",
        isAdmin: false
    }
]

const generateRefreshToken = (user) => {
    const refreshToken = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "refreshsecret");
    return refreshToken
}

const generateAccessToken = (user) => {
    const accessToken = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "secret", { expiresIn: '15m' });
    return accessToken;
}

app.post("/login", (req, res) => {
    const { username, password } = req.body
    const user = users.find((u) => {
        return u.username === username && u.password === password
    })

    if (user) {
        // GENERATE ACCESS TOKEN

        const accessToken = generateAccessToken(user)
        const refreshToken = generateRefreshToken(user)
        refreshTokens.push(refreshToken)

        res.json({
            username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        })


    } else {
        res.status(400).json("Username or password incorrect");
    }
})

const verify = (req, res, next) => {
    const authHeader = req.headers.authorization
    if (authHeader) {
        const token = authHeader.split(" ")[1]
        jwt.verify(token, "secret", (err, user) => {
            if (err) res.status(403).json("Token is not valid");
            req.user = user
            next();
        });
    } else {
        res.status(401).json("You are not authenticate")
    }
}

app.delete("/users/:userId", verify, (req, res) => {
    if (req.user.id === req.params.userId || req.user.isAdmin) {
        res.status(200).send("User has been deleted");
    } else {
        res.status(403).json("You are not allowed to delete this user")
    }
})

app.post("/refresh", (req, res) => {
    // TAKE THR REFRESH TOKEN FROM THE USER
    const refreshToken = req.body.token

    // SEND ERROR IF THERE IS NO TOKEN OR INVALID
    if (!refreshToken) return res.status(401).json("You are not authenticated!")
    if (!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("Refresh token is not valid");
    }

    jwt.verify(refreshToken, "refreshsecret", (err, user) => {
        if (err) console.log(err);

        // INVALIDATING PREVIOUS TOKEN
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken)

        // CREATING NEW TOKENS
        const newAccessToken = generateAccessToken(user)
        const newRefreshToken = generateRefreshToken(user);

        // PUSHING REFRESH TOKEN TO REFRESHTOKENS ARRAY
        refreshTokens.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })
    })
    // IF EVERYTHING IS OKAY, CREATE A NEW ACCESS TOKEN
    // AND SEND IT TO USER
})

app.post("/logout", verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter((token)=> token !== refreshToken)
    res.status(200).json("You logged out successfully");
})

app.listen(3000, () => {
    console.log("Server Started " + 3000);
})