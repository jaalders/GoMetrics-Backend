require('dotenv').config();

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');

app.use(cors());
app.use(express.json());

// our refreshTokens would be stored in a database or in a redis cache. But this will work locally for now.
let refreshTokens = [];

const posts = [
    {
        username: "Jeremy",
        title: "Post 1"
    },
    {
        username: "Blake",
        title: "Post 2"
    },
    {
        username: "test@test.com",
        title: "this is the test endpoint to see if username with email works."
    }
]

// DEVELOPER NOTE: Don't ever do this in production, if you are going to implement this code, please use a database to do password checking.
const users = [
    {
        id: "1",
        email: "test@test.com",
        password: "12password",
        name: "Jeremy Aalders"
    }
]

// call function to evaluate the given token.
app.get('/posts', authenicateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name));
});

app.post('/login', (req, res) => {
    // Authenticate User

    // We need to add the checking logic here for password comparison and encoding and such, but for this example we're just going to assume it's correct and let them go.
    if (users[0].email === req.body.email && users[0].password === req.body.password) {
        console.log("matching email/pass");
        const username = req.body.email;
        const user = {
            name : username
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
            expiresIn: "7d"
        });
        // now we have a copy of the refresh token in our tokens array for comparison.
        refreshTokens.push(refreshToken);
        
        // the only token we need to send back to the end user is the refresh token.
        res.json({ 
            accessToken: accessToken, 
            refreshToken: refreshToken 
        });
        console.log(refreshTokens);
    } else {
        res.status(403).send("User Not Authenicated");
    }

    // // this section below would be used with Postman Retrieve Login & Refresh Token
    // const username = req.body.username;
    // const user = { 
    //     name: username
    // };

    // const accessToken = generateAccessToken(user);
    // const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
    // // now we have a copy of the refresh token in our tokens array for comparison.
    // refreshTokens.push(refreshToken);
    
    // res.json({ 
    //     accessToken: accessToken, 
    //     refreshToken: refreshToken 
    // });

});

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    // send a delete status back to the HTTP request.
    res.sendStatus(204);
});

app.post('/renewaccessstoken', (req, res) => {
    const refreshToken = req.body.token;
    
    if (!refreshToken || !refreshTokens.includes(refreshToken)) {
        return res.status(403).send("User Not Authenicated");
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (!err) {
            const accessToken = jwt.sign({name: user.name}, process.env.ACCESS_TOKEN_SECRET, {
                expiresIn: "20s"
            });
            return res.json({
                accessToken: accessToken
            });
        } else {
            console.log(err);
            return res.status(403).send("User Not Authenicated");
        }
    });
});

// app.get('/validateRequest', authenicateToken, (req, res) => {
//     const authHeader = req.headers['authorization'];
//     const oldRefreshToken = authHeader.split(' ')[1];

//     console.log(oldRefreshToken);

//     if (refreshTokens.includes(oldRefreshToken)) {
        
//         console.log(refreshTokens);

//         // remove old refreshToken from array since it will be renewed.
//         refreshTokens = refreshTokens.filter(token => token !== oldRefreshToken);

//         console.log(refreshTokens)
//         console.log(user);

//         // generate new refreshToken
//         const newRefreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
//             expiresIn: "1h"
//         });

//         // now we have a copy of the refresh token in our tokens array for comparison.
//         refreshTokens.push(newRefreshToken);

//         console.log(refreshTokens);

//         // the only token we need to send back to the end user is the refresh token.
//         res.json({ 
//             refreshToken: newRefreshToken 
//         });

//     } else {
//         return res.sendStatus(403);
//     }
// });

app.post('/token', (req, res) => {
    const refreshToken = req.body.token;
    
    if (refreshToken == null) {
        res.sendStatus(401);
    }

    // if the refresh token does not exist in our refresh tokens array we want to return a 403 to the end user.
    if (!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403);
    }

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403);  
        }

        console.log(user.name);
        const accessToken = generateAccessToken({ 
            name: user.name 
        });
        
        // this token generated here is the refresh token used for POST calls.
        res.json({ 
            accessToken: accessToken 
        });
    });
});

function authenicateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    
    // if we have a authHeader, then return the authHeader token portion of the header, otherwise return undefined.
    const token = authHeader.split(' ')[1];

    if (token == null) {
        // 401 - Unauthorized
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            // 403 - Forbidden
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

function generateAccessToken(user) {
   return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
       expiresIn: "20s"
    });
}

app.listen(3000);