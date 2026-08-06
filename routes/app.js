var router = require('express').Router()
var appHandler = require('../core/appHandler')
var authHandler = require('../core/authHandler')

module.exports = function (csrfProtection) {
    router.get('/', authHandler.isAuthenticated, function (req, res) {
        res.redirect('/learn')
    })

    router.get('/usersearch', authHandler.isAuthenticated, csrfProtection, function (req, res) {
        res.render('app/usersearch', {
            output: null,
            csrfToken: req.csrfToken()
        })
    })

    router.get('/ping', authHandler.isAuthenticated, csrfProtection, function (req, res) {
        res.render('app/ping', {
            output: null,
            csrfToken: req.csrfToken()
        })
    })

    router.get('/bulkproducts', authHandler.isAuthenticated, csrfProtection, function (req, res) {
        res.render('app/bulkproducts',{
            legacy:req.query.legacy,
            csrfToken: req.csrfToken()
        })
    })

    router.get('/products', authHandler.isAuthenticated, appHandler.listProducts)

    router.get('/modifyproduct', authHandler.isAuthenticated, csrfProtection, appHandler.modifyProduct)

    router.get('/useredit', authHandler.isAuthenticated, csrfProtection, appHandler.userEdit)

    router.get('/calc', authHandler.isAuthenticated, csrfProtection, function (req, res) {
        res.render('app/calc',{
            output:null,
            csrfToken: req.csrfToken()
        })
    })

    router.get('/admin', authHandler.isAuthenticated, function (req, res) {
        res.render('app/admin', {
            admin: (req.user.role == 'admin')
        })
    })

    router.get('/admin/usersapi', authHandler.isAuthenticated, appHandler.listUsersAPI)

    router.get('/admin/users', authHandler.isAuthenticated, function(req, res){
        res.render('app/adminusers')
    })

    router.get('/redirect', appHandler.redirect)

    // POST routes with CSRF protection
    router.post('/usersearch', authHandler.isAuthenticated, csrfProtection, appHandler.userSearch)

    router.post('/ping', authHandler.isAuthenticated, csrfProtection, appHandler.ping)

    router.post('/products', authHandler.isAuthenticated, csrfProtection, appHandler.productSearch)

    router.post('/modifyproduct', authHandler.isAuthenticated, csrfProtection, appHandler.modifyProductSubmit)

    router.post('/useredit', authHandler.isAuthenticated, csrfProtection, appHandler.userEditSubmit)

    router.post('/calc', authHandler.isAuthenticated, csrfProtection, appHandler.calc)

    router.post('/bulkproducts', authHandler.isAuthenticated, csrfProtection, appHandler.bulkProducts);

    router.post('/bulkproductslegacy', authHandler.isAuthenticated, csrfProtection, appHandler.bulkProductsLegacy);

    return router
}
