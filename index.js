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
var bubble = require('bubble_babble');
var cookieParser = require('cookie-parser');

var redis = require('redis');
var client = redis.createClient({return_buffers: true});


// if an error occurs, print it to the console
client.on('error', function (err) {
    console.log("Redis error: " + err);
});

var config = {};
config.port = process.env.PORT || 3000;
config.root = process.env.ROOT_URL || ('http://localhost:' + config.port);

function secretCode(filename) {
    var code = crypto.createHash('sha256').update(filename + keyAndSecret.secret, 'utf8').digest('hex');
    return crypto.createHash('sha256').update(code + keyAndSecret.secret, 'utf8').digest('hex');
}

function hmacForStudent(studentId) {
    const hmac = crypto.createHmac('sha1', keyAndSecret.hmac );
    hmac.update(studentId);
    var encoded = bubble.encode(hmac.digest());
    return studentId + "-" + encoded;
}

console.log( hmacForStudent('017') );

function ltiLogin (req, identifier, profile, done) {
    done(null, profile);
}

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(passport.initialize());
passport.use('lti', new LtiStrategy(config.root, ltiLogin));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.get('/', function (req, res) {
    res.render('index');
});

app.use('/node_modules', express.static(path.join(__dirname, 'node_modules'), {maxAge: '1y'}));
app.use('/public', express.static(path.join(__dirname, 'public')));

function protocolAndHostname( req ) {
    return 'http://' + req.hostname + ':3000/';
}

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
	launchUrl: protocolAndHostname(req) + req.params.path + '/lti',
	domain: req.hostname
    };
        
    res.render('config', hash);
});

var pug = require('pug');
var passback = pug.compileFile(path.join(__dirname,'views/passback.pug'));

function submitAssignment(req, res, profile, completePath, callback) {
    // var completePath = 'users/' + profile.custom_canvas_user_id + '/' + req.params.path;
    var redirect = protocolAndHostname(req) + secretCode(completePath) + '/' + completePath;
    
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

    var key = "submit:" + profile.user_id + ":" + completePath;
    
    client.get(key, function(err, result) {
	if ((!err) && (result)) {
	    // submit only once
	    res.redirect(redirect);
	    callback(null, {});    
	} else {
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
		    // Don't submit again
		    client.set( key, true );
		}
	    });
	}
    });
}

// DEPRECATED: this is just so exam 1 still is visible
app.post('/1/:path(*)/lti', function(req, res, next) {
  passport.authenticate('lti', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.redirect('/'); }

      var completePath = 'users/' + user.custom_canvas_user_id + '/1/' + req.params.path;      
      var redirect = protocolAndHostname(req) + secretCode(completePath) + '/' + completePath;
      res.redirect(redirect);

  })(req, res, next);

});

app.get('/qr/', function(req,res,next) {
    res.render('qr', {code: '', valid: false});
});

app.get('/qr/:code', function(req,res,next) {
    var code = req.params.code;
    var valid = false;

    if (code) {
	res.cookie('qr', code);
	var id = code.split('-')[0];
	valid = (hmacForStudent(id) == code);
    }

    res.render('qr', {code: code, valid: valid});
});

app.post('/qr/', function(req,res,next) {
    var code = req.body.code;
    var valid = false;

    if (code) {
	res.cookie('qr', code);
	var id = code.split('-')[0];
	valid = (hmacForStudent(id) == code);
    }

    res.render('qr', {code: code, valid: valid});
});

app.post('/2/:path(*)/lti', function(req, res, next) {
  passport.authenticate('lti', function(err, user, info) {
      if (err) { return next(err); }
      if (!user) { return res.redirect('/'); }

      //console.log(user);
      
      var qr = req.cookies.qr;
      if ((qr !== undefined) && (qr != 'undefined')){
	  var code = qr.split('-')[0];
	  if (hmacForStudent(code) == qr){ 
	      var completePath = 'exams/2/' + code + '/' + req.params.path;
	      submitAssignment( req, res, user, completePath, function(err, result) {
		  if (err) {
		      next(err);
		  } else {
		      console.log(result);
		  }
	      });
	      return;
	  }
      }

      res.redirect(protocolAndHostname(req) + 'qr/' );
      return;
      
  })(req, res, next);

});

app.listen(config.port, function () {
    console.log('otterscan on port ' + config.port);
});
