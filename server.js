require('dotenv').config()

const express = require("express");
const app = express();
const jwt = require('jsonwebtoken')

app.use(express.json())

//les differents posts
const posts = [
    {
        username: "fab",
        title: "Badaboum"
    },
    {
        username: "manon",
        title: "beauvais"
    }
]

//stock les tokens de refresh (plus optim dans une BDD)
let refreshTokens = []


//recuperer les posts de l'utilisateur
app.get("/posts", authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username  === req.user.name))
})

//refresh le token avec le refreshtoken
app.post('/token' , (req,res) => {
    const refreshToken = req.body.token
    if(refreshToken == null) return res.sendStatus(401)

    if(!refreshTokens.includes(refreshToken)) res.sendStatus(403)

    //verifie le refresh token 
    jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken })
    })
})

//se deconnecter (supprime le refresh token)
app.delete('/logout', (req,res) => {
    //supprime le refresh token
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

//connexion (generer jwt token)
app.post("/login", (req,res) => {
    const username = req.body.username
    const user = { name: username }
    const accessToken = generateAccessToken(user)
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    
    //ajoute le refresh Token
    refreshTokens.push(refreshToken)

    //Renvoie les deux token
    res.json({ accessToken: accessToken, refreshToken : refreshToken })
})

//Verifie sur le jwt token est valide
function authenticateToken(req, res, next)
{
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(token == null) return res.sendStatus(401)

    //verifie le token
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET,(err,user) => {
        if(err) return res.sendStatus(403)

        req.user = user
        next()
    })
}

//generer un token de connection
function generateAccessToken(user)
{
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '15s'})
}

app.listen(3000)
