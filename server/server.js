require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mariadb = require('mariadb');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors({ origin: 'http://localhost:43635', credentials: true }));
app.use(bodyParser.json());

// Middlewares
app.use(bodyParser.json());
app.use(cookieParser());

// MariaDB connection pool
const pool = mariadb.createPool({
    host: 'localhost',
    user: 'appuser',
    password: 'password',
    database: 'userAuth',
    connectionLimit: 5
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { firstName, email, password } = req.body;
    if (!firstName || !email || !password) return res.status(400).send('All fields are required');

    let conn;
    try {
        conn = await pool.getConnection();
        
        const [existingUser] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser) return res.status(400).send('User already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        await conn.query('INSERT INTO users (first_name, email, password) VALUES (?, ?, ?)', [firstName, email, hashedPassword]);

        res.status(201).send('User registered successfully');
    } catch (err) {
        res.status(500).send('Server error');
        console.error(err);
    } finally {
        if (conn) conn.end();
    }
});
// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('All fields are required');

    let conn;
    try {
        conn = await pool.getConnection();
        
        const [user] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(400).send('Invalid email or password');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid email or password');

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.send('Login successful');
    } catch (err) {
        res.status(500).send('Server error');
        console.error(err);
    } finally {
        if (conn) conn.end();
    }
});

// Protected route (post-login page)
app.get('/dashboard', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).send('Access Denied');

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        res.send('Welcome to your dashboard');
    } catch (err) {
        res.status(400).send('Invalid Token');
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});