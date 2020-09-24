
'use strict';
const box = require('box-node-sdk');
const jwtDecode = require('jwt-decode');
var fs = require('fs');

const boxAppSettings ={
  "boxAppSettings": {
    "clientID": "",
    "clientSecret": "",
    "appAuth": {
      "publicKeyID": "",
      "privateKey": "",
      "passphrase": ""
    }
  },
  "enterpriseID": ""
}

let serviceAccountClient;

console.log("Using config file...");
let configFile =boxAppSettings;
let session = box.getPreconfiguredInstance(configFile);
serviceAccountClient = session.getAppAuthClient('enterprise');

/******************************************************************************
 * Module dependencies.
 *****************************************************************************/
var bodyParser = require('body-parser');

var express = require('express');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var passport = require('passport');
var util = require('util');
var config = require('./config');



// Start QuickStart here

var OIDCStrategy = require('passport-azure-ad').OIDCStrategy;


/******************************************************************************
 * Set up passport in the app 
 ******************************************************************************/

//-----------------------------------------------------------------------------
// To support persistent login sessions, Passport needs to be able to
// serialize users into and deserialize users out of the session.  Typically,
// this will be as simple as storing the user ID when serializing, and finding
// the user by ID when deserializing.
//-----------------------------------------------------------------------------
passport.serializeUser(function(user, done) {
  done(null, user.oid);
});

passport.deserializeUser(function(oid, done) {
  console.log("calling from deser");

  findByOid(oid, function (err, user) {
    done(err, user);
  });
});

// array to hold logged in users
var users = [];

var findByOid = function(oid, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    console.log('we are using user: '+ user.sub);
    if (user.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

//-----------------------------------------------------------------------------
// Use the OIDCStrategy within Passport.
// 
// Strategies in passport require a `verify` function, which accepts credentials
// (in this case, the `oid` claim in id_token), and invoke a callback to find
// the corresponding user object.
// 
// The following are the accepted prototypes for the `verify` function
// (1) function(iss, sub, done)
// (2) function(iss, sub, profile, done)
// (3) function(iss, sub, profile, access_token, refresh_token, done)
// (4) function(iss, sub, profile, access_token, refresh_token, params, done)
// (5) function(iss, sub, profile, jwtClaims, access_token, refresh_token, params, done)
// (6) prototype (1)-(5) with an additional `req` parameter as the first parameter
//
// To do prototype (6), passReqToCallback must be set to true in the config.
//-----------------------------------------------------------------------------
passport.use(new OIDCStrategy({
    identityMetadata: config.creds.identityMetadata,
    clientID: config.creds.clientID,
    responseType: config.creds.responseType,
    responseMode: config.creds.responseMode,
    redirectUrl: config.creds.redirectUrl,
    allowHttpForRedirectUrl: config.creds.allowHttpForRedirectUrl,
    clientSecret: config.creds.clientSecret,
    validateIssuer: config.creds.validateIssuer,
    isB2C: config.creds.isB2C,
    issuer: config.creds.issuer,
    passReqToCallback: config.creds.passReqToCallback,
    scope: config.creds.scope,
    loggingLevel: config.creds.loggingLevel,
    nonceLifetime: config.creds.nonceLifetime,
    nonceMaxAmount: config.creds.nonceMaxAmount,
    useCookieInsteadOfSession: config.creds.useCookieInsteadOfSession,
    cookieEncryptionKeys: config.creds.cookieEncryptionKeys,
    clockSkew: config.creds.clockSkew,
  },
  function(iss, sub, profile, accessToken, refreshToken, done) {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      console.log("calling from passport");
      findByOid(profile.oid, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
          users.push(profile);
          return done(null, profile);
        } 
        else {
          return done(null, user);
        }
        
      });
    });
  }
));


//-----------------------------------------------------------------------------
// Config the app, include middlewares
//-----------------------------------------------------------------------------
var app = express();

app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(express.logger());
app.use(methodOverride());
app.use(cookieParser());
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))

var jsonParser = bodyParser.json()
var urlencodedParser = bodyParser.urlencoded({ extended: false });

app.use(expressSession({ secret: 'keyboard cat', resave: true, saveUninitialized: false }));

app.use(bodyParser.urlencoded({ extended : true }));

// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.static('public'))

//-----------------------------------------------------------------------------
// Set up the route controller
//
// 1. For 'login' route and 'returnURL' route, use `passport.authenticate`. 
// This way the passport middleware can redirect the user to login page, receive
// id_token etc from returnURL.
//
// 2. For the routes you want to check if user is already logged in, use 
// `ensureAuthenticated`. It checks if there is an user stored in session, if not
// it will call `passport.authenticate` to ask for user to log in.
//-----------------------------------------------------------------------------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
};

app.get('/', function(req, res) {
  console.log
  res.render('index', { user: req.user });
});

app.post('/', function(req, res) {
  console.log
  res.render('index', { user: req.user });
});
app.get('/login',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        resourceURL: config.resourceURL,    // optional. Provide a value if you want to specify the resource.
        customState: 'my_state',            // optional. Provide a value if you want to provide custom state value.
        failureRedirect: '/fail' 
      }
    )(req, res, next);
  },
  function(req, res) {
    console.log("REQ:" + req);
    console.log('Login was called in the Sample');
    res.redirect('/');
});
app.post('/boxUI', urlencodedParser, function (req, res) {
  console.log("tok:" + req.body.userId);
  console.log("tok:" + JSON.stringify(req.body));
  let azId= req.body.userId;
	getAppUserID(azId)
		.then((appUserID) => {
			//If the box user is not present in AZURE, throw error
			if (!appUserID || appUserID=='NOTFOUND') {
				res.json({error: "some error"});
			}
			else {
				console.log(`App User ID is: ${appUserID.id}`);
				session.getAppUserTokens(appUserID.id).then(function(accessToken) {
					console.log("the access token is: " + accessToken);
					res.json({
            accessToken: accessToken.accessToken,
						azId:azId,
						userName:appUserID.name,
						login:appUserID.login,
						extId:appUserID.extId,
						boxId:appUserID.id
          });
				})
			}
		});
});
// 'GET returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// query (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
app.get('/auth/openid/return',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        failureRedirect: '/fail'  
      }
    )(req, res, next);
  },
  function(req, res) {
    console.log('We received a return from AzureAD.' + JSON.stringify(req.body));
    res.redirect('/');
  });

// 'POST returnURL'
// `passport.authenticate` will try to authenticate the content returned in
// body (such as authorization code). If authentication fails, user will be
// redirected to '/' (home page); otherwise, it passes to the next middleware.
app.post('/auth/openid/return',
  function(req, res, next) {
    passport.authenticate('azuread-openidconnect', 
      { 
        response: res,                      // required
        failureRedirect: '/fail'  
      }
    )(req, res, next);
  },
  function(req, res) {
    console.log('We received a return from AzureAD. - create here!' + JSON.stringify(req.body));
    var decoded = jwtDecode( req.body.id_token);
    console.log("DEC:" + JSON.stringify(decoded));
    console.log("OID:" + decoded.oid + "::" + decoded.name);
    getAppUserID(decoded.oid).then((appuserId) => {
      if(appuserId=='NOTFOUND') {
        createAppUser(decoded.oid,decoded.name).then((appUserID) => {
          console.log("created:" + appUserID);
          res.redirect('/');
        })
      }
      else {
        console.log("found:" + appuserId);
          res.redirect('/');
      }
    });
  });

// 'logout' route, logout from passport, and destroy the session with AAD.
app.get('/logout', function(req, res){
  req.session.destroy(function(err) {
    req.logOut();
    res.redirect(config.destroySessionUrl);
  });
});
app.get('/fail', function(req, res){
  res.json({"fail":"here"});
  });
  var port = process.env.PORT || 3000;
app.listen(port);
const createAppUser = (azId,name) =>   {
  console.log(azId + ":" + name);
  return serviceAccountClient.enterprise.addAppUser(name, { "is_platform_access_only": true,"external_app_user_id":azId }).then((result) => {
    console.log(result);
      
        return result.id;
      }
    );
}
const getAppUserID = (azId) => {
  console.log("Finding extID:" + azId);
  return serviceAccountClient.enterprise.getUsers({ "external_app_user_id": azId,"fields":"id,name,login,external_app_user_id" })
      .then((result) => {
          console.log(result);
          if (result.total_count > 0) {
            return {id:result.entries[0].id,name:result.entries[0].name,login:result.entries[0].login,extId:result.entries[0].external_app_user_id};
          }
          else {
            return "NOTFOUND";
          }
      });
}