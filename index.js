const express = require('express');
const app = express();
const passport = require('passport');
const path = require('path');
var LtiStrategy = require('./passport-lti').Strategy;
const bodyParser = require('body-parser');
var pug = require('pug');

var config = {};
config.port = process.env.PORT || 3000;
config.root = process.env.ROOT_URL || ('http://localhost:' + config.port);

function ltiLogin (req, identifier, profile, done) {
    done(null, profile);
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());
passport.use('lti', new LtiStrategy(config.root, ltiLogin));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.get('/', function (req, res) {
    res.render('index');
});

app.get('/:path(*)/lti.xml', function(req, res) {
    var hash = {
	title: 'Otterscan',
	description: '',
	launchUrl: req.protocol + ':' + req.hostname + '/' + req.params.path + '/lti',
	domain: req.hostname
    };
        
    res.render('config', hash);
});

app.post('/:path(*)/lti', function(req, res, next) {
  passport.authenticate('lti', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.redirect('/'); }
      console.log(user);
      res.render('index');	  

  })(req, res, next);

});

app.listen(config.port, function () {
    console.log('otterscan on port ' + config.port);
});
