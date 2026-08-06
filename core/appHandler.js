var db = require('../models')
var bCrypt = require('bcrypt')
const { spawn } = require('child_process');
var mathjs = require('mathjs')
var libxmljs = require("libxmljs");
const Op = db.Sequelize.Op

module.exports.userSearch = function (req, res) {
	// Fixed: Use parameterized query to prevent SQL injection
	db.User.findAll({
		where: {
			login: req.body.login
		},
		attributes: ['name', 'id']
	}).then(users => {
		if (users.length) {
			var output = {
				user: {
					name: users[0].name,
					id: users[0].id
				}
			}
			res.render('app/usersearch', {
				output: output,
				csrfToken: req.csrfToken()
			})
		} else {
			req.flash('warning', 'User not found')
			res.render('app/usersearch', {
				output: null,
				csrfToken: req.csrfToken()
			})
		}
	}).catch(err => {
		req.flash('danger', 'Internal Error')
		res.render('app/usersearch', {
			output: null,
			csrfToken: req.csrfToken()
		})
	})
}

module.exports.ping = function (req, res) {
	// Fixed: Validate input and use spawn instead of exec to prevent command injection
	var address = req.body.address;
	
	// Validate IP address or hostname format
	var validPattern = /^[a-zA-Z0-9.-]+$/;
	if (!address || !validPattern.test(address)) {
		return res.render('app/ping', {
			output: 'Invalid address format'
		});
	}
	
	// Use spawn with separate arguments to prevent command injection
	const ping = spawn('ping', ['-c', '2', address]);
	var output = '';
	
	ping.stdout.on('data', (data) => {
		output += data.toString();
	});
	
	ping.stderr.on('data', (data) => {
		output += data.toString();
	});
	
	ping.on('close', (code) => {
		res.render('app/ping', {
			output: output
		});
	});
	
	// Timeout after 10 seconds
	setTimeout(() => {
		ping.kill();
	}, 10000);
}

module.exports.listProducts = function (req, res) {
	db.Product.findAll().then(products => {
		output = {
			products: products
		}
		res.render('app/products', {
			output: output
		})
	})
}

module.exports.productSearch = function (req, res) {
	db.Product.findAll({
		where: {
			name: {
				[Op.like]: '%' + req.body.name + '%'
			}
		}
	}).then(products => {
		output = {
			products: products,
			searchTerm: req.body.name
		}
		res.render('app/products', {
			output: output,
			csrfToken: req.csrfToken()
		})
	})
}

module.exports.modifyProduct = function (req, res) {
	if (!req.query.id || req.query.id == '') {
		output = {
			product: {}
		}
		res.render('app/modifyproduct', {
			output: output,
			csrfToken: req.csrfToken()
		})
	} else {
		db.Product.find({
			where: {
				'id': req.query.id
			}
		}).then(product => {
			if (!product) {
				product = {}
			}
			output = {
				product: product
			}
			res.render('app/modifyproduct', {
				output: output,
				csrfToken: req.csrfToken()
			})
		})
	}
}

module.exports.modifyProductSubmit = function (req, res) {
	if (!req.body.id || req.body.id == '') {
		req.body.id = 0
	}
	db.Product.find({
		where: {
			'id': req.body.id
		}
	}).then(product => {
		if (!product) {
			product = new db.Product()
		}
		product.code = req.body.code
		product.name = req.body.name
		product.description = req.body.description
		product.tags = req.body.tags
		product.save().then(p => {
			if (p) {
				req.flash('success', 'Product added/modified!')
				res.redirect('/app/products')
			}
		}).catch(err => {
			output = {
				product: product
			}
			req.flash('danger',err)
			res.render('app/modifyproduct', {
				output: output
			})
		})
	})
}

module.exports.userEdit = function (req, res) {
	res.render('app/useredit', {
		userId: req.user.id,
		userEmail: req.user.email,
		userName: req.user.name,
		csrfToken: req.csrfToken()
	})
}

module.exports.userEditSubmit = function (req, res) {
	// Fixed: Check authorization - users can only edit their own profile
	if (req.body.id != req.user.id) {
		req.flash('danger', 'Unauthorized: You can only edit your own profile')
		return res.redirect('/app/useredit')
	}
	
	db.User.find({
		where: {
			'id': req.body.id
		}		
	}).then(user =>{
		if(!user){
			req.flash('danger', 'User not found')
			return res.redirect('/app/useredit')
		}
		
		if(req.body.password.length>0){
			if(req.body.password.length>0){
				if (req.body.password == req.body.cpassword) {
					user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null)
				}else{
					req.flash('warning', 'Passwords dont match')
					res.render('app/useredit', {
						userId: req.user.id,
						userEmail: req.user.email,
						userName: req.user.name,
					})
					return		
				}
			}else{
				req.flash('warning', 'Invalid Password')
				res.render('app/useredit', {
					userId: req.user.id,
					userEmail: req.user.email,
					userName: req.user.name,
				})
				return
			}
		}
		user.email = req.body.email
		user.name = req.body.name
		user.save().then(function () {
			req.flash('success',"Updated successfully")
			res.render('app/useredit', {
				userId: req.body.id,
				userEmail: req.body.email,
				userName: req.body.name,
			})
		})
	})
}

module.exports.redirect = function (req, res) {
	// Fixed: Validate redirect URL to prevent open redirect attacks
	if (req.query.url) {
		// Only allow relative URLs (starting with /) or same-origin URLs
		var url = req.query.url;
		
		// Check if it's a relative URL
		if (url.startsWith('/') && !url.startsWith('//')) {
			return res.redirect(url);
		}
		
		// Check if it's a same-origin URL
		try {
			var urlObj = new URL(url, 'http://' + req.get('host'));
			if (urlObj.hostname === req.get('host')) {
				return res.redirect(url);
			}
		} catch (e) {
			// Invalid URL
		}
		
		res.send('Invalid redirect: Only internal redirects are allowed')
	} else {
		res.send('invalid redirect url')
	}
}

module.exports.calc = function (req, res) {
	// Fixed: Use safe evaluation with limited scope to prevent code injection
	if (req.body.eqn) {
		try {
			// Create a limited scope math parser
			const limitedEval = mathjs.create({
				matrix: 'Array'
			});
			
			// Remove potentially dangerous functions
			limitedEval.import({
				import: function () { throw new Error('Function import is disabled') },
				createUnit: function () { throw new Error('Function createUnit is disabled') },
				evaluate: function () { throw new Error('Function evaluate is disabled') },
				parse: function () { throw new Error('Function parse is disabled') },
				simplify: function () { throw new Error('Function simplify is disabled') },
				derivative: function () { throw new Error('Function derivative is disabled') }
			}, { override: true });
			
			// Validate input - only allow mathematical expressions
			var eqn = req.body.eqn;
			var dangerousPattern = /(import|eval|Function|process|require|child_process|exec)/i;
			if (dangerousPattern.test(eqn)) {
				throw new Error('Invalid expression');
			}
			
			// Limit length to prevent DoS
			if (eqn.length > 200) {
				throw new Error('Expression too long');
			}
			
			var result = limitedEval.evaluate(eqn);
			res.render('app/calc', {
				output: result
			})
		} catch (error) {
			res.render('app/calc', {
				output: 'Error: Invalid mathematical expression'
			})
		}
	} else {
		res.render('app/calc', {
			output: 'Enter a valid math string like (3+3)*2'
		})
	}
}

module.exports.listUsersAPI = function (req, res) {
	// Fixed: Don't expose sensitive data like passwords
	// Also add authorization check - only admins should see user list
	if (req.user.role !== 'admin') {
		return res.status(403).json({
			success: false,
			message: 'Unauthorized: Admin access required'
		})
	}
	
	db.User.findAll({
		attributes: ['id', 'name', 'email', 'login', 'role']
	}).then(users => {
		res.status(200).json({
			success: true,
			users: users
		})
	})
}

module.exports.bulkProductsLegacy = function (req,res){
	// Fixed: Use JSON instead of insecure deserialization
	if(req.files.products){
		try {
			var products = JSON.parse(req.files.products.data.toString('utf8'))
			
			if (!Array.isArray(products)) {
				throw new Error('Invalid format: expected array of products')
			}
			
			products.forEach( function (product) {
				// Validate product data
				if (!product.name || !product.code) {
					throw new Error('Invalid product data: name and code are required')
				}
				
				var newProduct = new db.Product()
				newProduct.name = product.name
				newProduct.code = product.code
				newProduct.tags = product.tags || ''
				newProduct.description = product.description || ''
				newProduct.save()
			})
			res.redirect('/app/products')
		} catch (error) {
			res.render('app/bulkproducts',{messages:{danger:'Invalid file format. Please upload valid JSON.'},legacy:true})
		}
	}else{
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:true})
	}
}

module.exports.bulkProducts =  function(req, res) {
	// Fixed: Disable external entity processing to prevent XXE attacks
	if (req.files.products && req.files.products.mimetype=='text/xml'){
		try {
			// Parse XML with noent set to false to disable external entities
			var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {
				noent: false,    // Disable external entity expansion
				nonet: true,     // Disable network access
				noblanks: true
			})
			
			// Validate XML structure
			if (!products.root()) {
				throw new Error('Invalid XML structure')
			}
			
			products.root().childNodes().forEach( product => {
				var childNodes = product.childNodes()
				if (childNodes.length < 4) {
					return; // Skip invalid products
				}
				
				var newProduct = new db.Product()
				newProduct.name = childNodes[0].text()
				newProduct.code = childNodes[1].text()
				newProduct.tags = childNodes[2].text()
				newProduct.description = childNodes[3].text()
				newProduct.save()
			})
			res.redirect('/app/products')
		} catch (error) {
			res.render('app/bulkproducts',{messages:{danger:'Invalid XML file'},legacy:false})
		}
	}else{
		res.render('app/bulkproducts',{messages:{danger:'Invalid file'},legacy:false})
	}
}
