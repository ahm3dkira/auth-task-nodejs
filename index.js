const express = require("express")
const mongoose = require("mongoose")
const User = require("./models/user")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const dotenv = require("dotenv")
const cors = require("cors")

dotenv.config()
const app = express()
app.use(express.json())
app.use(cors())


mongoose.connect(process.env.DB_CONNECTION, { useNewUrlParser: true, useUnifiedTopology: true })
    .then((res) => {
        // only listen for requests once database data has loaded
        const PORT = process.env.PORT || 5000
        app.listen(PORT, () => console.log("Server is live"))
    }
    )
    .catch(err => console.log(err))

app.post("/register", async (req, res) => {
    let {email, password, username} = req.body.email
    console.log(email, password, username)
    // check if username or email has been taken by another user already
    const takenUsername = await User.findOne({ username: username })
    const takenEmail = await User.findOne({ email: email })
    if (takenUsername || takenEmail) {
        res.json({ message: "Username or email has already been taken" })
    }
    else {
        password = await bcrypt.hash(password, 10)
        const dbUser = new User({
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: password
        })
        dbUser.save()
        res.json({ message: "Success" })
    }
})
app.post("/login", (req, res) => {
    const userLoggingIn = req.body;
    console.log(req.body)
    User.findOne({ username: userLoggingIn.username })
        .then(dbUser => {
            if (!dbUser) {
                return res.json({
                    message: "Invalid Username or Password"
                })
            }
            bcrypt.compare(userLoggingIn.password, dbUser.password)
                .then(isCorrect => {
                    if (isCorrect) {
                        const payload = {
                            id: dbUser._id,
                            username: dbUser.username,
                        }
                        jwt.sign(
                            payload,
                            process.env.JWT_SECRET,
                            { expiresIn: 86400 }, // 24 hours
                            (err, token) => {
                                if (err) return res.json({ message: err })
                                return res.json({
                                    message: "Success",
                                    token: token
                                })
                            }
                        )
                    } else {
                        return res.json({
                            message: "Invalid Username or Password"
                        })
                    }
                })
            
        })
})

function verifyJWT(req, res, next) {
    // const token = req.headers["x-access-token"]?.split(' ')[1]
    // const token = req.headers["Authorization"]?.split(' ')[1]
    // console.log(req.headers["Authorization"])
    const token = req.header("Authorization").split(" ")[1];
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return res.json({
                isLoggedIn: false,
                message: "Failed To Authenticate"
            })
            req.user = {}
            req.user.id = decoded.id
            req.user.username = decoded.username
            next()
        })
    } else {
        res.json({ message: "Incorrect Token Given", isLoggedIn: false })
    }
}
/*
app.get ("/getUsername", verifyJwT, (reg, res) => {
res. json({isLoggedIn: true, username: req. user . username})
})
*/
app.get("/getUsername", verifyJWT, (req, res) => {
    res.json({ isLoggedIn: true, username: req.user.username })
})

// each user has a secret message that only they can see and edit
app.get("/getSecretMessage", verifyJWT, (req, res) => {
    User.findById(req.user.id)
        .then(dbUser => {
            res.json({ secretMessage: dbUser.secretMessage })
        })
})
app.post("/setSecretMessage", verifyJWT, (req, res) => {
    // update the secret message of the user
    let newSecretMessage = req.body.secretMessage
    console.log(newSecretMessage)
    User.findByIdAndUpdate(req.user.id, { secretMessage: newSecretMessage })
        .then(dbUser => {
            res.json({ message: "secret message updated" });
        })
})