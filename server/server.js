require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mariadb = require('mariadb');
const axios = require('axios');


const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors({ 
    origin: ['https://isa-project-client.netlify.app', 'https://www.isa-project-client.netlify.app'], 
    credentials: true 
}));
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

app.get('/predict/:symbol', async (req, res) => {
    const { symbol } = req.params;

    try {
        // Making a GET request to the external API
        const response = await axios.get(`https://ankitahlwat1.pythonanywhere.com/predict?symbol=${symbol}`);

        // Sending the response data back to the client
        res.status(200).json(response.data);
    } catch (error) {
        console.error('Error fetching data from API:', error.message);
        res.status(500).send('Failed to fetch data from external API');
    }
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

        const isAdmin = user.email === 'admin';

        const token = jwt.sign({ userId: user.id, isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, {
            httpOnly: false,  // Makes it inaccessible to JavaScript on the client (good for security)
        });
        res.send('Login successful');
    } catch (err) {
        res.status(500).send('Server error');
        console.error(err);
    } finally {
        if (conn) conn.end();
    }
});

app.get('/users', async (req, res) => {
    const token = req.cookies.token;

    // Check if token is present
    if (!token) {
        return res.status(401).send('Unauthorized');
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Check if the user has admin privileges
        if (!decoded.isAdmin) {
            return res.status(403).send('Forbidden: Admins only');
        }

        // Database connection
        let conn;
        try {
            conn = await pool.getConnection();

            // Query all users' data (first_name, email, requests)
            const query = 'SELECT first_name, email, requests FROM users';
            const results = await conn.query(query);

            // Send results as JSON
            res.json(results);
        } catch (dbError) {
            console.error(dbError);
            res.status(500).send('Database error');
        } finally {
            if (conn) conn.end();
        }
    } catch (jwtError) {
        console.error(jwtError);
        res.status(403).send('Invalid token');
    }
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});