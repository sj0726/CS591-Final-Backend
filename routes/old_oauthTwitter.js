//An example showing OAuth 1.0 against Twitter
//perryd@bu.edu @perrydBUCS

//Get a router instance
//
const express = require('express')
const router = express.Router()
const request = require('request-promise')

//const jwt = require('jsonwebtoken')
//const jwtConfig = require('../Config/jwtConfig')
//We're going to store info on users in mongo with a schema defined in
//mongoose, so get a connection and grab the crypto version of the user model (because crypto)
//
const User = require('../models/UserWithCrypto')
const checkAuthorization = require('./checkAuthorization')

//We're also going to pass the access token back and forth in a
//JSON Web Token (jwt) that is placed in a cookie, so we'll need
//a jwt package
//
const jwt = require('jsonwebtoken')
let myTweet
let targetLang = 'ko'
let myUserID
let myAuthor
let translatedText
let detectedLanguage

//We're using the twitter package to simplify the interaction
//
const twitterAPI = require('twitter')

//Grab configs for Twitter and jwt
//
const twitterConfig = require('../Config/twitter')
const jwtConfig = require('../Config/jwtConfig')

//We're using the oauth package to simplify things a bit, especially signing
//requests.
//
const oauth = require('oauth').OAuth

//Set up oauth with 3rd party info from config file
//
const oa = new oauth(
    twitterConfig.REQ_TOKEN_URL,
    twitterConfig.ACCESS_TOKEN_URL,
    twitterConfig.CONSUMER_KEY,
    twitterConfig.CONSUMER_SECRET,
    twitterConfig.OAUTH_VERSION,
    twitterConfig.CALLBACK_URL,
    twitterConfig.ALGORITHM
)

//Route to display a simple pug template
//
router.get('/', function (req, res, next) {
    res.render('twitterAccount', {})
})

//This route is hit from a 'Log In With Twitter' button on the front end
//
router.get('/twitter', function (req, res, next) {
    //1. getOAuthRequestToken hits requests a Request token from the OAuth provider
    //(Twitter in this case) using the credentials provided in the constructor above.
    //It will send: consumer_key, signature_method, signature, timestamp, nonce,
    //version, and callback URL. On success the callback function is invoked with
    //the Request token and secret as received from Twitter. The 'results' object
    //seems to only have a flag to indicate if the callback URL passed to Twitter
    //matches what was set up when the app was created on the Twitter side
    //
    oa.getOAuthRequestToken(function (error, oauth_token, oauth_token_secret, results) {
        if (error) {
            console.log(error)
            res.render('twitterAccount', {error: 'Unable to grant access token'})
        }
        else {
            //Put the token and secret on the session, then redirect the user's browser
            //to Twitter so that they can log in and authorize this request token
            //
            req.session.oauth = {}
            req.session.oauth.token = oauth_token
            console.log('oauth.token: ' + req.session.oauth.token)
            req.session.oauth.token_secret = oauth_token_secret
            console.log('oauth.token_secret: ' + req.session.oauth.token_secret)

            //2. User is sent to Twitter here...oauth_token is an UNAUTHORIZED Request token
            //to be authorized by the user as part of logging in to Twitter. You can think of it
            //as being a blank Request token at this point. Even though the OAuth 1.0 spec says that
            //the token is optional, just about every auth provider requires it; if it isn't there,
            //the provider would prompt the user to enter it manually, which can't be a good thing.
            //
            res.redirect('https://twitter.com/oauth/authenticate?oauth_token=' + oauth_token)
        }
    })

})

//3. This route is invoked from Twitter once the user has logged in there and given the app the
//permissions requested. Both the callback and the requested permissions are defined
// when setting up the app on the Twitter side
//
router.get('/callback', function (req, res, next) {
    if (req.session.oauth) {
        req.session.oauth.verifier = req.query.oauth_verifier;
        const oauth = req.session.oauth;

        //Here we exchange the authorized Request token for an Access token. This request is
        //signed (as all requests must be) with a key that has two parts separated by an &:
        //CONSUMER_SECRET&TOKEN_SECRET. We got TOKEN_SECRET from Twitter in the response
        //to the request for a Request token, and we own the CONSUMER_SECRET. On Twitter's
        //side they will construct the request from scratch based on both the passed params
        //and headers and re-run the signing algorithm to verify the signature (this is why
        //we aren't passing the CONSUMER_SECRET...Twitter already has it from when we set up
        //the app on their side.
        //
        //As best I can figure, oauth_verifier is being used to verify the issuer of this
        //request; it is different from the nonce, which is used to ensure that the Request token
        //isn't being re-used.
        //
        oa.getOAuthAccessToken(oauth.token, oauth.token_secret, oauth.verifier,

            //4. This function is the callback for getOAuthAccessToken. We now have
            //an Access token and secret from Twitter for this specific user, and
            //we no longer need the Request token (it's a one-time use token). The
            //results object contains the user's screen name and Twitter ID.
            //
            //At this point we can store the token and secret in our local database,
            //since we'll need it any time that a request is sent to Twitter to get
            //something from the user's account or feed.
            //
            //We can place the token (but not the secret) in a JWT and use it as an authentication token
            //for our own app; makes sense to place the JWT on a cookie marked httpOnly.
            //just be sure to delete the cookie when the user logs out. To implement a
            //'keep me logged in' function the token could be dropped into local storage
            //on the browser.
            //
            function (error, oauth_access_token, oauth_access_token_secret, results) {
                if (error) {
                    console.log(error);
                    res.render('twitterAccount', {'error': error});
                } else {
                    const twitterID = results.user_id
                    req.session.oauth.access_token = oauth_access_token;
                    req.session.oauth.access_token_secret = oauth_access_token_secret;
                    console.log(results);

                    //Store user info in mongo
                    //

                    User.findOneAndUpdate({twitterID: twitterID},
                        {
                            twitterID: twitterID,
                            name: results.screen_name,
                            username: results.screen_name,
                            twitterAccessToken: oauth_access_token,
                            twitterAccessTokenSecret: oauth_access_token_secret
                        },
                        {'upsert': 'true'},
                        function (err, result) {
                            if (err) {
                                console.log(err)
                            }
                            else {
                                console.log("Updated", results.screen_name, "in database.")
                            }
                        })
                    //The user is now authenticated with Twitter, and we can send control
                    //back to the browser. (This is in a single-page app, and so we always
                    //return to the / route)
                    //
                    //But first :^) we'll generate a jwt and drop it into a cookie to be sent back and forth
                    //The jwt package takes care of the header, so we simply need to construct
                    //the payload and then sign it. We'll simplify things a bit by using a hash signature
                    //instead of an RSA signature
                    const jwtPayload = {
                        twitterAccessToken: oauth_access_token
                    }

                    const authJwtToken = jwt.sign(jwtPayload, jwtConfig.jwtSecret)

                    //Note that this cookie is visible on the client side ONLY for demo
                    //purposes. You'd want to set this to httpOnly to prevent the cookie
                    //from being opened on the client side, as in
                    const cookieOptions = {
                        httpOnly: false,
                        expires: 0 //Makes this a session-only cookie
                    }
                    res.cookie('twitterAccessJwt', authJwtToken, cookieOptions)
                    //
                    //res.render('twitterAccount', {loggedIn: true})
                    //res.redirect('http://localhost:4200/home')
                    console.log('hit the callback function')
                    res.redirect('https://localhost:4200/home')
                }
            }
        );
    } else
        next(new Error("Error: OAuth object was not present on this session."))
})

//This route returns an authenticated Twitter user's account settings
//
router.get('/showAccount', checkAuthorization, function (req, res, next) {
    //This part of the route will run only for an authenticated user; the
    // checkAuthorization method places the valid user object on the request

    const user = req.user

    //Hit Twitter to get this user's account information; use the twitter
    //package to simplify the call. The API is described at
    // https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-settings
    //
    const client = new twitterAPI({
        consumer_key: twitterConfig.CONSUMER_KEY,
        consumer_secret: twitterConfig.CONSUMER_SECRET,
        access_token_key: user.twitterAccessToken,
        access_token_secret: user.twitterAccessTokenSecret
    });
    client.get(twitterConfig.urls.ACCOUNT_SETTINGS_URL, function (err, account, response) {
        console.log(err, account)
        res.render('twitterAccount', {account: account, loggedIn: true})
    })
})



router.get('/showTweets', checkAuthorization, function(req, res, next) {
//router.get('/showTweets', function(req, res, next) {
    /*
         req.user = user
         User.findOne({'twitterAccessToken': userJWTPayload.twitterAccessToken})
             .then(function (user) {
                 if (!user) {
                     res.send(401, 'User not currently logged in')
                 }
                 else {
                     req.user = user
                     console.log('Valid user:', user.name)
                     next()
                 }

             })




        const client = new twitterAPI({
            consumer_key: twitterConfig.CONSUMER_KEY,
            consumer_secret: twitterConfig.CONSUMER_SECRET,
            access_token_key: user.twitterAccessToken,
            access_token_secret: user.twitterAccessTokenSecret
        });
        let params = {
            tweet_mode: 'extended'
        }

        client.get('favorites/list', params, function(error, tweets, response) {
            if (error) throw error;
            // console.log(tweets);
            myTweet = tweets[0].full_text;
            myAuthor = tweets[0].user.name;
            myUserID = tweets[0].user.screen_name;
            targetLang = 'ko';
    /*        console.log(myAuthor);
            console.log(myUserID);*/


    //res.send(myTweet)
    const options = { method: 'POST',
        url: 'https://translation.googleapis.com/language/translate/v2',
        qs: { key: 'AIzaSyBI-GW7GH5hHmz_41BcGcPv_dpGGrLoGEQ' },
        headers:
            { 'Postman-Token': '337e4abc-14b1-476f-a2bf-8058fb44481f',
                'Cache-Control': 'no-cache',
                'Content-Type': 'application/x-www-form-urlencoded' },
        form: { 'q': myTweet, target: 'ko' } };

    request(options, function (error, response, body) {
        if (error) throw new Error(error);

        let result = JSON.parse(body)
        let result2 = result.data.translations[0]
        let translatedText = result2.translatedText
        let detectedLanguage = result2.detectedSourceLanguage
        //console.log(result)
        res.json({myTweet, myUserID , myAuthor, translatedText, detectedLanguage, targetLang})
    });
});


//This route logs the user out:
//1. Delete the cookie
//2. Delete the access key and secret from the user record in mongo
//
router.get('/logout', checkAuthorization, function (req, res, next) {
    const userJWT = req.cookies.twitterAccessJwt
    const userJWTPayload = jwt.verify(userJWT, jwtConfig.jwtSecret)

    res.clearCookie('twitterAccessJwt')
    User.findOneAndUpdate({twitterAccessToken: userJWTPayload.twitterAccessToken},
        {
            twitterAccessToken: null,
            twitterAccessTokenSecret: null
        },
        function (err, result) {
            if (err) {
                console.log(err)
            }
            else {
                console.log("Deleted access token for", result.name)
            }
            res.render('twitterAccount', {loggedIn: false})
        })

})

module.exports = router