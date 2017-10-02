const express = require('express');
const app = express();
const passport = require('passport');
const path = require('path');
const fs = require('fs');
var LtiStrategy = require('./passport-lti').Strategy;
const bodyParser = require('body-parser');
var pug = require('pug');
const uuidv1 = require('uuid/v1');
var request = require('request');
var keyAndSecret = require("./key-and-secret.json");
const crypto = require('crypto');

var config = {};
config.port = process.env.PORT || 3000;
config.root = process.env.ROOT_URL || ('http://localhost:' + config.port);

function secretCode(filename) {
    var code = crypto.createHash('sha256').update(filename + keyAndSecret.secret, 'utf8').digest('hex');
    return crypto.createHash('sha256').update(code + keyAndSecret.secret, 'utf8').digest('hex');
}

console.log( secretCode('blank.pdf') );

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

app.get('/:code/:path(*)', function (req, res) {
    if (secretCode(req.params.path) == req.params.code) {
	var filename = path.join(__dirname, req.params.path);
	fs.stat(filename, function(err, stats) {
	    if (err) {
		res.status(500).send(err);
		return;
	    }
	    
	    var file = fs.createReadStream(filename);
	    res.setHeader('Content-Length', stats.size);
	    res.setHeader('Content-Type', 'application/pdf');
	    file.pipe(res);
	});
    } else {
	res.status(403).send('You do not have the passphrase for that file.');
    }
});

app.get('/:path(*)/lti.xml', function(req, res) {
    var hash = {
	title: 'Otterscan',
	description: '',
	launchUrl: 'https://' + req.hostname + '/' + req.params.path + '/lti',
	domain: req.hostname
    };
        
    res.render('config', hash);
});

var pug = require('pug');
var passback = pug.compileFile(path.join(__dirname,'views/passback.pug'));

function submitAssignment(req, res, profile, callback) {
    var completePath = 'users/' + profile.custom_canvas_user_id + '/' + req.params.path;
    
    var redirect = 'https://' + req.hostname + '/' + secretCode(completePath) + '/' + completePath;
    
    var pox = passback({
	messageIdentifier: uuidv1(),
	resultDataUrl: redirect,
	sourcedId: profile.lis_result_sourcedid
    });
				
    var url = profile.lis_outcome_service_url;
					
    var oauth = {
	callback: "about:blank",
	body_hash: true,			
	consumer_key: keyAndSecret.key,
	consumer_secret: keyAndSecret.secret,
	signature_method: profile.oauth_signature_method
    };

    request.post({
	url: url,
	body: pox,
	oauth: oauth,
	headers: {
	    'Content-Type': 'application/xml',
	}
    }, function(err, response, body) {
	if (err) {
	    callback(err);
	} else {
	    res.redirect(redirect);
	    callback(null, response);
	}
    });
}

app.post('/:path(*)/lti', function(req, res, next) {
  passport.authenticate('lti', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.redirect('/'); }

      console.log(user);
      
      submitAssignment( req, res, user, function(err, result) {
	  if (err) {
	      next(err);
	  } else {
	      console.log(result);
	  }
      });

  })(req, res, next);

});

app.listen(config.port, function () {
    console.log('otterscan on port ' + config.port);
});
