// Security Vulnerability Examples for Testing Security Scanners

const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cookieParser());

// SECURITY VULNERABILITY: Hardcoded JWT secret
const JWT_SECRET = "my-super-secret-jwt-key-12345";
const JWT_ALGORITHM = "HS256";

// SECURITY VULNERABILITY: Hardcoded API tokens
const STRIPE_API_KEY = "sk_live_51H3ll0W0rld1234567890abcdef";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SECURITY VULNERABILITY: Exposed credentials in environment variables (hardcoded)
process.env.DATABASE_PASSWORD = "SuperSecretPassword123!";
process.env.API_SECRET = "my-api-secret-key-456";

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/users', {
    user: 'admin',
    pass: 'hardcoded_password_here'
});

// SECURITY VULNERABILITY: Logging user passwords in plaintext
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log(`Login attempt: username=${username}, password=${password}`);
    console.error(`Failed login for user: ${username} with password: ${password}`);
    
    // Log to file
    const fs = require('fs');
    fs.appendFileSync('app.log', `Login: ${username} / ${password}\n`);
    
    // SECURITY VULNERABILITY: NoSQL injection vulnerability
    const query = { username: username, password: password };
    mongoose.connection.db.collection('users').findOne(query, (err, user) => {
        if (err) {
            console.log(`Error: ${err}, Query: ${JSON.stringify(query)}`);
            return res.status(500).send('Error');
        }
        
        if (user) {
            // SECURITY VULNERABILITY: Insecure cookie settings
            res.cookie('session', jwt.sign({ userId: user._id }, JWT_SECRET), {
                httpOnly: false,  // Should be true
                secure: false,     // Should be true in production
                sameSite: 'none'  // Insecure
            });
            
            res.send('Login successful');
        } else {
            res.send('Login failed');
        }
    });
});

// SECURITY VULNERABILITY: XSS in template rendering
app.get('/welcome', (req, res) => {
    const name = req.query.name || 'Guest';
    
    // XSS vulnerability - unescaped user input
    const html = `
        <html>
            <body>
                <h1>Welcome, ${name}!</h1>
                <script>
                    console.log('User: ${name}');
                </script>
            </body>
        </html>
    `;
    
    res.send(html);
});

// SECURITY VULNERABILITY: Logging sensitive tokens
app.post('/api/authenticate', (req, res) => {
    const token = req.body.token;
    
    console.log(`Authentication token received: ${token}`);
    logger.info(`Token: ${token}`);
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ success: true, user: decoded });
    } catch (err) {
        console.log(`Invalid token: ${token}`);
        res.status(401).json({ error: 'Invalid token' });
    }
});

// SECURITY VULNERABILITY: Exposed API keys in response
app.get('/config', (req, res) => {
    res.json({
        stripeKey: STRIPE_API_KEY,
        awsAccessKey: AWS_ACCESS_KEY,
        awsSecretKey: AWS_SECRET_KEY,
        jwtSecret: JWT_SECRET
    });
});

// SECURITY VULNERABILITY: Command injection via child_process
app.post('/execute', (req, res) => {
    const { command } = req.body;
    
    const { exec } = require('child_process');
    exec(`ls -la ${command}`, (error, stdout, stderr) => {
        if (error) {
            console.log(`Error: ${error.message}`);
            return res.status(500).send('Error');
        }
        res.send(stdout);
    });
});

// SECURITY VULNERABILITY: Insecure file operations
app.get('/file', (req, res) => {
    const filename = req.query.filename;
    const fs = require('fs');
    
    // Path traversal vulnerability
    const filePath = `/var/www/uploads/${filename}`;
    const content = fs.readFileSync(filePath, 'utf8');
    res.send(content);
});

const logger = {
    info: (msg) => {
        const fs = require('fs');
        fs.appendFileSync('app.log', `[INFO] ${msg}\n`);
    }
};

app.listen(3000, () => {
    console.log('Server running on port 3000');
    console.log(`Database password: ${process.env.DATABASE_PASSWORD}`);
});

