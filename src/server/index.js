// Main starting point of the application
const schedule = require('node-schedule');
const parser = require('cron-parser');
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const passport = require('passport');
const requireSignin = passport.authenticate('local', {session: false});
const requireAuth = passport.authenticate('jwt', {session: false});
const jsonWebToken = require('jwt-simple');
const config = require('./config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
const bcrypt = require('bcrypt-nodejs');
const Schema = mongoose.Schema;




//************Database Setup*****************
mongoose.connect('mongodb://localhost:TF_ServersProject/TF_ServersProject');
//*******************************************



//************App Setup*****************
app.use(morgan('combined')); // login framework its for debugging...
app.use(cors());
app.use(bodyParser.json({
    type: '*/*'
}));
router(app);
//**************************************



//************Server Setup*****************
const port = process.env.PORT || 3090;
const server = http.createServer(app);
server.listen(port);
console.log('Server listening on:', port);

//*****************************************







//************Router Function*****************
function router(app) {
    app.get('/', requireAuth, function(req, res) {
        res.send({
            message: 'login message'
        });
    });
    app.post('/signin', requireSignin, signin);
    app.post('/signup', signup);
}
//*********************************************




//************DataBsae Mongodb user Model*****************

// Define our model
const userSchema = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true
    },
    password: String
});


// Before saving a model, run this function
userSchema.pre('save', function(next) {
    // get access to the user model
    const user = this;

    // generate a salt then run callback
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return next(err);
        }

        // hash (encrypt) our password using the salt
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) {
                return next(err);
            }

            // overwrite plain text password with encrypted password
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(userPassword, callback) {
    bcrypt.compare(userPassword, this.password, function(err, isMatch) {
        if (err) {
            return callback(err);
        }

        callback(null, isMatch);
    });
}

// Create the model class
const ModelClass = mongoose.model('user', userSchema);

//*************************************************************





//************Authentication Functions*****************

function signin(req, res, next) {
    //
    // ModelClass has already had their email and password 
    //moongose added user credentials to the req obj.  (req.user)
    // now the user will get a token
    res.send({
        token: tokenForUser(req.user)
    });
}

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jsonWebToken.encode({
        sub: user.id,
        iat: timestamp
    }, config.secret);
}


function signup(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;

    if (!email || !password) {
        return res.status(422).send({
            error: 'You must provide email and password'
        });
    }

    // See if a user with the given email exists
    ModelClass.findOne({
        email: email
    }, function(err, existingUser) {
        if (err) {
            return next(err);
        }

        // If a user with email does exist, return an error
        if (existingUser) {
            return res.status(422).send({
                error: 'The Email is allready Exist'
            });
        }

        // If a user with email does NOT exist, create and save user record
        const user = new ModelClass({
            email: email,
            password: password
        });

        user.save(function(err) {
            if (err) {
                return next(err);
            }

            // Repond to request indicating the user was created
            res.json({
                token: tokenForUser(user)
            });
        });
    });
}

//**********************************************************



//****************************Passport Service************************

// Create local strategy
const localOptions = {
    usernameField: 'email'
};
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
    // Verify this email and password, call done with the user
    // if it is the correct email and password
    // otherwise, call done with false
    ModelClass.findOne({
        email: email
    }, function(err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false);
        }

        // compare passwords - is `password` equal to user.password?
        user.comparePassword(password, function(err, isMatch) {
            if (err) {
                return done(err);
            }
            if (!isMatch) {
                return done(null, false);
            }

            return done(null, user);
        });
    });
});



// Setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
    // See if the user ID in the payload exists in our database
    // If it does, call 'done' with that other
    // otherwise, call done without a user object
    ModelClass.findById(payload.sub, function(err, user) {
        if (err) {
            return done(err, false);
        }

        if (user) {
            done(null, user);
        } else {
            done(null, false);
        }
    });
});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
//*********************************************************