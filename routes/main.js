var router = require('express').Router()
var vulnDict = require('../config/vulns')
var authHandler = require('../core/authHandler')

module.exports = function (passport, csrfProtection) {
	router.get('/', authHandler.isAuthenticated, function (req, res) {
		res.redirect('/learn')
	})

	router.get('/login', authHandler.isNotAuthenticated, csrfProtection, function (req, res) {
		res.render('login', {
			csrfToken: req.csrfToken()
		})
	})

	router.get('/learn/vulnerability/:vuln', authHandler.isAuthenticated, function (req, res) {
		res.render('vulnerabilities/layout', {
			vuln: req.params.vuln,
			vuln_title: vulnDict[req.params.vuln],
			vuln_scenario: req.params.vuln + '/scenario',
			vuln_description: req.params.vuln + '/description',
			vuln_reference: req.params.vuln + '/reference',
			vulnerabilities:vulnDict
		}, function (err, html) {
			if (err) {
				console.log(err)
				res.status(404).send('404')
			} else {
				res.send(html)
			}
		})
	})

	router.get('/learn', authHandler.isAuthenticated, function (req, res) {
		res.render('learn',{vulnerabilities:vulnDict})
	})

	router.get('/register', authHandler.isNotAuthenticated, csrfProtection, function (req, res) {
		res.render('register', {
			csrfToken: req.csrfToken()
		})
	})

	router.get('/logout', function (req, res) {
		req.logout();
		res.redirect('/');
	})

	router.get('/forgotpw', csrfProtection, function (req, res) {
		res.render('forgotpw', {
			csrfToken: req.csrfToken()
		})
	})

	router.get('/resetpw', csrfProtection, authHandler.resetPw)

	// POST routes with CSRF protection
	router.post('/login', csrfProtection, passport.authenticate('login', {
		successRedirect: '/learn',
		failureRedirect: '/login',
		failureFlash: true
	}))

	router.post('/register', csrfProtection, passport.authenticate('signup', {
		successRedirect: '/learn',
		failureRedirect: '/register',
		failureFlash: true
	}))

	router.post('/forgotpw', csrfProtection, authHandler.forgotPw)

	router.post('/resetpw', csrfProtection, authHandler.resetPwSubmit)

	return router
}