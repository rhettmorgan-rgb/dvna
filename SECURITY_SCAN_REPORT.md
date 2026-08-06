# Security Scan Report
## Damn Vulnerable NodeJS Application (DVNA)

**Scan Date:** August 6, 2026  
**Repository:** https://github.com/rhettmorgan-rgb/dvna  
**Branch:** master  
**Repository Size:** 7.8 MB  
**JavaScript Files:** 14 files

---

## Executive Summary

This repository contains **Damn Vulnerable NodeJS Application (DVNA)**, an intentionally vulnerable Node.js web application designed for educational purposes. The application demonstrates OWASP Top 10 vulnerabilities and serves as a training platform for developers and security professionals to learn about web application security.

### Key Findings

- **Purpose:** Educational security training application
- **Technology Stack:** Node.js, Express, Sequelize ORM, EJS templating, MySQL
- **Vulnerabilities:** Intentionally implements 12 major vulnerability classes
- **Documentation:** Comprehensive developer security guide available
- **Deployment:** Docker-ready with multiple deployment options

---

## Repository Structure

### Core Components

```
dvna/
├── server.js                 # Main application entry point
├── package.json             # Dependencies and project metadata
├── docker-compose.yml       # Docker orchestration
├── Dockerfile               # Production container image
├── Dockerfile-dev           # Development container image
├── core/                    # Application core modules
│   ├── appHandler.js       # Main application logic
│   ├── authHandler.js      # Authentication logic
│   └── passport.js         # Passport.js configuration
├── routes/                  # Route definitions
│   ├── main.js             # Main routes (auth, register, etc.)
│   └── app.js              # Application routes
├── models/                  # Database models
│   ├── index.js            # Sequelize initialization
│   ├── user.js             # User model
│   └── product.js          # Product model
├── views/                   # EJS templates
│   ├── app/                # Application views
│   └── vulnerabilities/    # Vulnerability documentation views
├── config/                  # Configuration files
│   ├── db.js               # Database configuration
│   ├── server.js           # Server configuration
│   └── vulns.js            # Vulnerability mappings
├── public/                  # Static assets
└── docs/                    # Documentation
```

---

## Technology Stack Analysis

### Core Dependencies

| Package | Version | Purpose | Status |
|---------|---------|---------|--------|
| express | ^4.16.2 | Web framework | ⚠️ Outdated |
| sequelize | ^4.13.10 | ORM | ⚠️ Major version behind |
| mysql2 | ^1.4.2 | MySQL driver | ⚠️ Outdated |
| passport | ^0.4.0 | Authentication | ⚠️ Outdated |
| bcrypt | ^1.0.3 | Password hashing | ⚠️ Outdated |
| ejs | ^2.5.7 | Templating | ⚠️ Known vulnerabilities |
| libxmljs | ^0.19.1 | XML parsing | ⚠️ Potential vulnerabilities |
| node-serialize | 0.0.4 | Serialization | ⚠️ Known insecure |
| mathjs | 3.10.1 | Math evaluation | ⚠️ Code injection risk |

**Note:** These outdated/vulnerable dependencies are **intentional** as this is a vulnerable-by-design application for training purposes.

---

## Intentional Vulnerabilities Catalog

The application implements the following vulnerability classes for educational purposes:

### OWASP Top 10 (2017)

1. **A1: Injection**
   - SQL Injection in user search functionality
   - Command Injection in ping functionality
   - Location: `core/appHandler.js` lines 10, 38-44

2. **A2: Broken Authentication**
   - Weak session management
   - Insecure session secret: "keyboard cat"
   - Location: `server.js` line 24

3. **A3: Sensitive Data Exposure**
   - Passwords visible in API responses
   - No HTTPS enforcement
   - Location: `core/appHandler.js` lines 206-213

4. **A4: XML External Entities (XXE)**
   - Unsafe XML parsing with entity expansion enabled
   - Location: `core/appHandler.js` line 235

5. **A5: Broken Access Control**
   - Horizontal privilege escalation
   - Missing authorization checks
   - Location: `routes/app.js`, `core/appHandler.js`

6. **A6: Security Misconfiguration**
   - Debug mode enabled
   - Default configurations
   - Verbose error messages

7. **A7: Cross-Site Scripting (XSS)**
   - Reflected XSS in product search
   - DOM-based XSS
   - Location: Multiple view templates

8. **A8: Insecure Deserialization**
   - node-serialize deserialization vulnerability
   - Location: `core/appHandler.js` line 218

9. **A9: Using Components with Known Vulnerabilities**
   - Multiple outdated and vulnerable dependencies
   - Location: `package.json`

10. **A10: Insufficient Logging and Monitoring**
    - Inadequate security event logging
    - No intrusion detection

### Additional Vulnerabilities (OWASP 2013)

11. **A8:2013 Cross-Site Request Forgery (CSRF)**
    - Missing CSRF tokens on state-changing operations
    - CSRF library included but not implemented

12. **A10:2013 Unvalidated Redirects and Forwards**
    - Open redirect vulnerability
    - Location: `core/appHandler.js` lines 186-192

---

## Critical Security Issues Analysis

### 1. SQL Injection (Critical)

**Location:** `core/appHandler.js:10`

```javascript
var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
```

**Issue:** Direct string concatenation in SQL query allows SQL injection attacks.

**Impact:** Full database compromise, data exfiltration, data manipulation.

### 2. Command Injection (Critical)

**Location:** `core/appHandler.js:38-44`

```javascript
exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
    output = stdout + stderr
    res.render('app/ping', {
        output: output
    })
})
```

**Issue:** Unsanitized user input passed directly to system command execution.

**Impact:** Remote code execution, system compromise.

### 3. Insecure Deserialization (Critical)

**Location:** `core/appHandler.js:218`

```javascript
var products = serialize.unserialize(req.files.products.data.toString('utf8'))
```

**Issue:** Untrusted data deserialization using node-serialize.

**Impact:** Remote code execution via crafted serialized objects.

### 4. XXE Injection (High)

**Location:** `core/appHandler.js:235`

```javascript
var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
```

**Issue:** XML parsing with entity expansion enabled (`noent:true`).

**Impact:** Local file disclosure, SSRF, denial of service.

### 5. Code Injection via Math Evaluation (High)

**Location:** `core/appHandler.js:194-203`

```javascript
res.render('app/calc', {
    output: mathjs.eval(req.body.eqn)
})
```

**Issue:** User input evaluated directly by mathjs without sanitization.

**Impact:** Remote code execution.

### 6. Weak Session Management (Medium)

**Location:** `server.js:23-28`

```javascript
app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
}))
```

**Issues:**
- Hardcoded weak session secret
- Cookies not marked secure
- No session timeout

### 7. Open Redirect (Medium)

**Location:** `core/appHandler.js:186-192`

```javascript
module.exports.redirect = function (req, res) {
	if (req.query.url) {
		res.redirect(req.query.url)
	}
}
```

**Issue:** Unvalidated redirect allows phishing attacks.

### 8. Missing Authorization Checks (High)

**Location:** `core/appHandler.js:144-184`

```javascript
db.User.find({
    where: {
        'id': req.body.id
    }		
})
```

**Issue:** User can edit any user account by manipulating the ID parameter.

**Impact:** Horizontal privilege escalation, account takeover.

---

## Application Architecture

### Authentication Flow

1. Uses Passport.js with local strategy
2. Passwords hashed with bcrypt (properly implemented)
3. Session-based authentication
4. Role-based access control (admin/user)

### Database Layer

- **ORM:** Sequelize v4
- **Supported Databases:** MySQL (primary), SQLite (quick start)
- **Models:** User, Product
- **Schema:** Auto-synchronized on startup

### Routing Structure

- `/` - Public routes (login, register, password reset)
- `/app/*` - Protected application routes (requires authentication)
- `/learn` - Vulnerability documentation and learning materials

---

## Deployment Options

### 1. Quick Start (SQLite)

```bash
docker run --name dvna -p 9090:9090 -d appsecco/dvna:sqlite
```

### 2. Development Setup (Docker Compose)

```bash
docker-compose up
```

Features:
- Auto-reload on code changes
- MySQL database
- Development debugging enabled

### 3. Production Setup

Requires:
- MySQL 5.7+ database
- Node.js environment
- Environment variables configuration

---

## Configuration Analysis

### Environment Variables Required

```bash
MYSQL_USER         # Database username
MYSQL_DATABASE     # Database name
MYSQL_PASSWORD     # Database password
MYSQL_HOST         # Database host
MYSQL_PORT         # Database port (default: 3306)
```

### Server Configuration

- **Port:** 9090 (default)
- **Session Secret:** Hardcoded (intentionally weak)
- **File Upload:** Enabled (no size limits configured)
- **Body Parser:** Extended URL encoding disabled
- **Static Files:** Served from `/public`

---

## Documentation and Resources

### Available Documentation

1. **Developer Security Guide** (https://appsecco.com/books/dvna-developers-security-guide/)
   - Setup instructions
   - Exploitation walkthroughs
   - Vulnerable code explanations
   - Fix recommendations
   - Security best practices

2. **In-App Learning Materials**
   - Description of each vulnerability
   - Exploitation scenarios
   - Reference materials
   - Located in `/views/vulnerabilities/`

3. **Solution Branches**
   - `fixes` branch: Contains vulnerability fixes
   - `fixes-2017` branch: OWASP Top 10 2017 specific fixes

---

## Git History Analysis

**Last Commit:** c637437 - "Update README.md"  
**Active Branches:**
- `master` (current)
- `remotes/origin/cursor/security-scan-report-bbc3`

**Recent Activity:**
- Documentation updates
- DOM XSS documentation improvements
- Quick start improvements
- Docs generation updates

---

## Security Assessment Summary

### Educational Purpose ✓

This application successfully serves its educational purpose by:
- Implementing real-world vulnerability patterns
- Providing comprehensive documentation
- Offering hands-on exploitation scenarios
- Including both vulnerable and fixed code versions

### Real-World Risk Assessment ⚠️

**If deployed in production (DO NOT):**

- **Critical Risk:** Remote code execution via multiple vectors
- **High Risk:** Complete database compromise
- **Medium Risk:** Session hijacking, account takeover
- **Low Risk:** Information disclosure, phishing

---

## Recommendations

### For Educational Use (Current Purpose)

1. ✅ Continue maintaining clear documentation
2. ✅ Keep vulnerability examples up-to-date with current OWASP standards
3. ✅ Add prominent warnings against production deployment
4. ✅ Consider adding OWASP Top 10 2021 vulnerabilities
5. ✅ Include automated testing examples

### For Production Deployment (If Adapted)

1. ❌ **Never deploy this application in production as-is**
2. ✅ Use the `fixes` branch as a starting point
3. ✅ Update all dependencies to latest secure versions
4. ✅ Implement input validation and sanitization
5. ✅ Add WAF (Web Application Firewall)
6. ✅ Enable HTTPS with proper TLS configuration
7. ✅ Implement proper logging and monitoring
8. ✅ Add rate limiting and CSRF protection
9. ✅ Use environment-specific configuration
10. ✅ Implement security headers

---

## Additional Findings

### Positive Security Practices

Despite being intentionally vulnerable, the application demonstrates some good practices:

1. **Password Hashing:** Uses bcrypt properly (not intentionally broken)
2. **ORM Usage:** Uses Sequelize for most database operations
3. **Modular Architecture:** Well-organized code structure
4. **Docker Support:** Modern deployment options
5. **Version Control:** Proper use of Git and branching

### Missing Security Features

1. ❌ No Content Security Policy (CSP) headers
2. ❌ No rate limiting
3. ❌ No input validation framework
4. ❌ No security-focused middleware (helmet.js, etc.)
5. ❌ No automated security testing in CI/CD
6. ❌ No dependency vulnerability scanning
7. ❌ No logging framework beyond basic morgan

---

## Testing Recommendations

### For Security Testing Practice

1. **SQL Injection Testing**
   - User search functionality (`/app/usersearch`)
   - Try: `' OR '1'='1`

2. **Command Injection Testing**
   - Ping functionality (`/app/ping`)
   - Try: `8.8.8.8; ls -la`

3. **XSS Testing**
   - Product search (`/app/products`)
   - Try: `<script>alert('XSS')</script>`

4. **XXE Testing**
   - Bulk products upload (`/app/bulkproducts`)
   - Upload XML with external entity definitions

5. **Deserialization Testing**
   - Legacy bulk products (`/app/bulkproductslegacy`)
   - Upload serialized payload

---

## Compliance and Standards

### OWASP Top 10 Coverage

| OWASP 2017 | Implemented | Educational Value |
|------------|-------------|-------------------|
| A1 - Injection | ✅ | High |
| A2 - Broken Authentication | ✅ | High |
| A3 - Sensitive Data Exposure | ✅ | Medium |
| A4 - XXE | ✅ | High |
| A5 - Broken Access Control | ✅ | High |
| A6 - Security Misconfiguration | ✅ | Medium |
| A7 - XSS | ✅ | High |
| A8 - Insecure Deserialization | ✅ | High |
| A9 - Using Components with Known Vulnerabilities | ✅ | Medium |
| A10 - Insufficient Logging | ✅ | Low |

---

## Conclusion

**Damn Vulnerable NodeJS Application (DVNA)** is a well-designed educational security training platform that successfully demonstrates critical web application vulnerabilities. The application achieves its educational goals by providing:

- Real-world vulnerability implementations
- Comprehensive documentation and learning materials
- Multiple deployment options for convenience
- Clear separation between vulnerable and fixed code

**⚠️ CRITICAL WARNING:** This application contains **intentional critical security vulnerabilities** and must **NEVER** be deployed in a production environment or on public-facing infrastructure. Use only in isolated, controlled environments for security training and testing purposes.

### Repository Health: Educational ✓ | Production ❌

---

## References

- OWASP Top 10 2017: https://owasp.org/www-project-top-ten/2017/
- Project Repository: https://github.com/appsecco/dvna
- Developer Guide: https://appsecco.com/books/dvna-developers-security-guide/
- Project Blog: https://blog.appsecco.com/damn-vulnerable-nodejs-application-dvna-by-appsecco-7d782d36dc1e

---

**Report Generated By:** Cursor Cloud Agent  
**Date:** August 6, 2026  
**Scan Type:** Comprehensive Repository Analysis
