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
const apiUrl = "https://isa-project-cxqx.onrender.com/";

app.use(cors({
    origin: 'https://isa-project-client.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'Set-Cookie'],
}));

// Middlewares
app.use(bodyParser.json());
app.use(cookieParser());

// MariaDB connection pool
const pool = mariadb.createPool({
    host: '127.0.0.1',
    user: 'appuser',
    password: 'password',
    database: 'userAuth',
    connectionLimit: 5
});

app.options('*', cors());
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

        const isAdmin = user.email === 'admin@admin.com';

        const token = jwt.sign({ email: user.email, isAdmin }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, {
            httpOnly: true,  // More secure to set this to true for a session token
            sameSite: 'None',  // Required for cross-site cookies
            secure: true       // Required for cookies over HTTPS
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

// TODO CAN YOU CHECK THESE WORK 
// Existing imports and setup code remain the same

// Add a PUT endpoint for updating user details
app.put('/users/:email', async (req, res) => {
    const { email } = req.params;
    const { firstName, requests } = req.body;
    const token = req.cookies.token; // Get the token from cookies

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Check if the user has admin privileges
        if (!decoded.isAdmin) {
            return res.status(403).send('Forbidden: Admins only');
        }

        if (!email || (!firstName && requests === undefined)) {
            return res.status(400).send('Invalid request. Provide email and at least one field to update.');
        }

        let conn;
        try {
            conn = await pool.getConnection();

            const userExists = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
            if (!userExists.length) {
                return res.status(404).send('User not found');
            }

            const updateFields = [];
            const updateValues = [];

            if (firstName) {
                updateFields.push('first_name = ?');
                updateValues.push(firstName);
            }

            if (requests !== undefined) {
                updateFields.push('requests = ?');
                updateValues.push(requests);
            }

            updateValues.push(email);

            const updateQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE email = ?`;
            await conn.query(updateQuery, updateValues);

            res.status(200).send('User updated successfully');
        } catch (err) {
            console.error(err);
            res.status(500).send('Server error');
        } finally {
            if (conn) conn.end();
        }
    } catch (err) {
        console.error(err);
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(403).send('Invalid token');
        }
        res.status(500).send('Server error');
    }
});


// Add a DELETE endpoint for deleting users
app.delete('/users/:email', async (req, res) => {
    const { email } = req.params;
    const token = req.cookies.token; // Get the token from cookies

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Check if the user has admin privileges
        if (!decoded.isAdmin) {
            return res.status(403).send('Forbidden: Admins only');
        }

        if (!email) {
            return res.status(400).send('Email is required');
        }

        let conn;
        try {
            conn = await pool.getConnection();

            const result = await conn.query('DELETE FROM users WHERE email = ?', [email]);
            if (result.affectedRows === 0) {
                return res.status(404).send('User not found');
            }

            res.status(200).send('User deleted successfully');
        } catch (err) {
            console.error(err);
            res.status(500).send('Server error');
        } finally {
            if (conn) conn.end();
        }
    } catch (err) {
        console.error(err);
        if (err instanceof jwt.JsonWebTokenError) {
            return res.status(403).send('Invalid token');
        }
        res.status(500).send('Server error');
    }
});

app.get('/api-consumption', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }

    try {
        // Decode the token to get the user's email
        const decoded = jwt.verify(token, JWT_SECRET);
        const userEmail = decoded.email;

        let conn;
        try {
            conn = await pool.getConnection();

            // Fetch the total API consumption for the user
            const [user] = await conn.query('SELECT requests FROM users WHERE email = ?', [userEmail]);

            if (!user) {
                return res.status(404).send('User not found');
            }

            res.status(200).json({ email: userEmail, totalRequests: user.requests });
        } catch (err) {
            console.error('Database error:', err);
            res.status(500).send('Internal server error');
        } finally {
            if (conn) conn.end();
        }
    } catch (err) {
        console.error('Token error:', err);
        res.status(403).send('Invalid token');
    }
});


// Ensure all connections require HTTPS (Part 6 of API Server I think)
app.use((req, res, next) => {
    if (!req.secure) {
        return res.status(400).send('HTTPS is required');
    }
    next();
});

// External API Logic
const verifyTokenAndFetchUser = async (token, REQUEST_LIMIT) => {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userEmail = decoded.email;

    let conn;
    let user;
    let outOfRequests = false;

    try {
        conn = await pool.getConnection();

        const [userData] = await conn.query('SELECT requests FROM users WHERE email = ?', [userEmail]);
        if (!userData) throw new Error('User not found');

        user = userData;

        // Check if the user has exceeded the request limit
        outOfRequests = user.requests >= REQUEST_LIMIT;

        // Update the requests count in the database
        const updateQuery = `
            UPDATE users
            SET requests = requests + 1
            WHERE email = ?;
        `;
        await conn.query(updateQuery, [userEmail]);

        console.log(`Requests count updated for user: ${userEmail}`);
    } finally {
        if (conn) conn.end();
    }

    return { outOfRequests, userEmail };
};

const fetchExternalAPI = async (url) => {
    try {
        const response = await axios.get(url);
        return response.data;
    } catch (error) {
        console.error('External API error:', error.message);
        throw new Error('Failed to fetch data from external API');
    }
};

const handleAPIRequest = (endpoint, apiUrlGenerator) => {
    return async (req, res) => {
        const { params } = req;
        const token = req.cookies.token; // Get the token from cookies

        if (!token) {
            return res.status(401).send('Unauthorized: No token provided');
        }

        try {
            const REQUEST_LIMIT = 20;
            const { outOfRequests, userEmail } = await verifyTokenAndFetchUser(token, REQUEST_LIMIT);

            const apiUrl = apiUrlGenerator(params);
            const data = await fetchExternalAPI(apiUrl);

            if (outOfRequests) {
                data.warning = 'You have exceeded the request limit.';
            }

            res.status(200).json(data);
        } catch (error) {
            console.error('Error:', error.message);
            if (error instanceof jwt.JsonWebTokenError) {
                return res.status(403).send('Invalid token');
            }
            res.status(500).send(error.message);
        }
    };
};

app.get(
    '/summary-info/:ticker',
    handleAPIRequest('summary-info', (params) => `${apiUrl}summary-info?ticker=${params.ticker}`)
);

app.get(
    '/predict/:symbol',
    handleAPIRequest('predict', (params) => `${apiUrl}predict?symbol=${params.symbol}`)
);
app.get(
    '/rsi/:ticker',
    handleAPIRequest('summary-info', (params) => `${apiUrl}rsi?ticker=${params.ticker}`)
);


// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});