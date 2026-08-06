var express = require('express')
var bodyParser = require('body-parser')
var passport = require('passport')
var session = require('express-session')
var ejs = require('ejs')
var morgan = require('morgan')
const fileUpload = require('express-fileupload');
var config = require('./config/server')
var helmet = require('helmet')
var csurf = require('csurf')
var crypto = require('crypto')

//Initialize Express
var app = express()
require('./core/passport')(passport)

// Security headers
app.use(helmet({
	contentSecurityPolicy: {
		directives: {
			defaultSrc: ["'self'"],
			styleSrc: ["'self'", "'unsafe-inline'"],
			scriptSrc: ["'self'"],
			imgSrc: ["'self'", "data:"],
			fontSrc: ["'self'"]
		}
	},
	hsts: {
		maxAge: 31536000,
		includeSubDomains: true,
		preload: true
	}
}))

app.use(express.static('public'))
app.set('view engine','ejs')
app.use(morgan('combined')) // More detailed logging
app.use(bodyParser.urlencoded({ extended: false }))
app.use(fileUpload({
	limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
	abortOnLimit: true
}));

// Enable for Reverse proxy support
// app.set('trust proxy', 1) 

// Generate secure session secret (use environment variable in production)
var sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// Fixed: Secure session configuration
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    httpOnly: true,
    maxAge: 3600000, // 1 hour session timeout
    sameSite: 'strict'
  }
}))

// Initialize Passport
app.use(passport.initialize())
app.use(passport.session())

// Initialize express-flash
app.use(require('express-flash')());

// CSRF Protection
var csrfProtection = csurf({ cookie: false })

// Make CSRF token available to all views
app.use(function(req, res, next) {
	res.locals.user = req.user;
	next();
})

// Routing
app.use('/app',require('./routes/app')(csrfProtection))
app.use('/',require('./routes/main')(passport, csrfProtection))

// Start Server
app.listen(config.port, config.listen)