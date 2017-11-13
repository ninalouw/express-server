const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

//setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey : config.secret
};

//create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
    //See if the user id in the payload esists in our db
    //if it does, call 'done' with that user
    //otherwise, call done without a user object
    User.findById(payload.sub, function(err, user){
        if(err){ return done(err, false);}
        if(user){
            done(null, user);
        } else {
            done(null, false);
        }
    });
});
//Tell passport to use this strategy
passport.use(jwtLogin);
