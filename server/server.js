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

// Middleware to redirect requests without version to /v1
app.use((req, res, next) => {
    // Check if the path doesn't start with "/v1" or "/v2"
    if (!req.path.startsWith('/v1') && !req.path.startsWith('/v2')) {
        console.log(`Redirecting request to /v1${req.path}`);
        req.url = `/v1${req.url}`; // Update the URL to include /v1
    }
    next(); // Pass control to the next middleware
});

const normalizePath = (path) => {
    // Replace dynamic segments (e.g., user IDs) with placeholders
    return path.replace(/\/\d+|\/[a-fA-F0-9]{24}|\/[^\s/]+/g, '/:id');
};

app.use((req, res, next) => {
    const normalizedPath = normalizePath(req.path); // Normalize the path
    console.log(`Endpoint called: ${req.method} ${normalizedPath}`);

    // Optionally, save this to the database if needed
    // Example:
    // await pool.query('INSERT INTO logs (method, endpoint) VALUES (?, ?)', [req.method, normalizedPath]);

    next();
});


// Middleware to log requests in the database
app.use(async (req, res, next) => {
    console.log("Request received");
    console.log(req.originalUrl);

    const token = req.cookies.token;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        user = decoded.userId;
    }
    catch (jwtError) {
        user = null;
    }

    console.log(user);

    console.log(req.method);
    if (!user || !req.originalUrl) return next(); // Skip if no userId or URL available

    let conn;
    try {
        console.log('inside try block');
        conn = await pool.getConnection();

        url = normalizedPath

        // Get or create endpoint ID
        let [endpoint] = await conn.query('SELECT id FROM endpoints WHERE endpoint = ? AND method = ?', [url, req.method]);
        if (!endpoint) {
            const result = await conn.query('INSERT INTO endpoints (endpoint, method) VALUES (?, ?)', [url, req.method]);
            endpoint = { id: result.insertId };
        }

        // Insert request record
        await conn.query('INSERT INTO requests (user_id, endpoint_id, timestamp) VALUES (?, ?, NOW())', [user, endpoint.id]);
    } catch (err) {
        console.error('Error logging request:', err.message);
    } finally {
        if (conn) conn.end();
    }
    next();
});

// register endpoint
app.post('/v1/register', async (req, res) => {
    const { firstName, email, password } = req.body;
    if (!firstName || !email || !password) return res.status(400).send('All fields are required');

    let conn;
    try {
        conn = await pool.getConnection();

        const [existingUser] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser) return res.status(400).send('User already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await conn.query('INSERT INTO users (first_name, email, password) VALUES (?, ?, ?)', [firstName, email, hashedPassword]);

        // Log the request with the newly created user ID
        req.userId = result.insertId;

        let [endpoint] = await conn.query('SELECT id FROM endpoints WHERE endpoint = ? AND method = ?', ['/register', req.method]);
        if (!endpoint) {
            const result = await conn.query('INSERT INTO endpoints (endpoint, method) VALUES (?, ?)', ['/register', req.method]);
            endpoint = { id: result.insertId };
        }

        // Insert request record
        await conn.query('INSERT INTO requests (user_id, endpoint_id, timestamp) VALUES (?, ?, NOW())', [req.userId, endpoint.id]);

        res.status(201).send('User registered successfully');
    } catch (err) {
        res.status(500).send('Server error');
        console.error(err);
    } finally {
        if (conn) conn.end();
    }
});

// Login endpoint
app.post('/v1/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send('All fields are required');

    let conn;
    try {
        conn = await pool.getConnection();

        const [user] = await conn.query('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(400).send('Invalid email or password');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid email or password');

        const isAdmin = Boolean(user.admin);

        const token = jwt.sign({ userId: user.id, isAdmin }, JWT_SECRET, { expiresIn: '1h' });
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

// Add a PUT endpoint for updating user details
app.put('/v1/users/:email', async (req, res) => {
    const { email } = req.params;
    const { newEmail } = req.body;
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

        if (!email || !newEmail) {
            return res.status(400).send('Invalid request. Provide new email.');
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

            if (newEmail) {
                updateFields.push('email = ?');
                updateValues.push(newEmail);
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
app.delete('/v1/users/:email', async (req, res) => {
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

// api-consumption endpoint
app.get('/v1/api-consumption', async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.status(401).send('Unauthorized: No token provided');
    }
    

    try {
        // Decode the token to get the user's email
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;
        

        let conn;
        try {
            requests = await getUserRequests(userId);

            res.status(200).json({ totalRequests: requests });
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

// Endpoint: Total requests per endpoint (Admin only)
app.get('/v1/endpoint-requests', async (req, res) => {
    const token = req.cookies.token; 

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Check if the user has admin privileges
        if (!decoded.isAdmin) {
            return res.status(403).send('Forbidden: Admins only');
        }

        let conn;
        try {
            conn = await pool.getConnection();

            const results = await conn.query(`
                SELECT e.method, e.endpoint, COUNT(r.id) AS total_requests
                FROM endpoints e
                LEFT JOIN requests r ON e.id = r.endpoint_id
                GROUP BY e.id;
            `);

            const processedResults = results.map(row => {
                return Object.fromEntries(
                    Object.entries(row).map(([key, value]) => [
                        key,
                        typeof value === 'bigint' ? Number(value) : value
                    ])
                );
            });

            res.json(processedResults);
        } catch (err) {
            console.error('Database error:', err.message);
            res.status(500).send('Server error');
        } finally {
            if (conn) conn.end();
        }
    } catch (err) {
        console.error('Authentication error:', err.message);
        res.status(401).send('Unauthorized: Invalid token');
    }
});

// Endpoint: Total requests per user (Admin only)
app.get('/v1/user-requests', async (req, res) => {
    const token = req.cookies.token;

    try {
        // Verify the token
        const decoded = jwt.verify(token, JWT_SECRET);

        // Check if the user has admin privileges
        if (!decoded.isAdmin) {
            return res.status(403).send('Forbidden: Admins only');
        }

        let conn;
        try {
            conn = await pool.getConnection();

            const results = await conn.query(`
                SELECT u.first_name AS user_name, u.email, COUNT(r.id) AS total_requests
                FROM users u
                LEFT JOIN requests r ON u.id = r.user_id
                GROUP BY u.id;
            `);

            const processedResults = results.map(row => {
                return Object.fromEntries(
                    Object.entries(row).map(([key, value]) => [
                        key,
                        typeof value === 'bigint' ? Number(value) : value
                    ])
                );
            });

            res.json(processedResults);
        } catch (err) {
            console.error('Database error:', err.message);
            res.status(500).send('Server error');
        } finally {
            if (conn) conn.end();
        }
    } catch (err) {
        console.error('Authentication error:', err.message);
        res.status(401).send('Unauthorized: Invalid token');
    }
});

// Endpoint: Check if the user is authenticated
app.get('/v1/auth-check', (req, res) => {
    const token = req.cookies.token; // Assuming you're using cookies for authentication

    try {
        if (!token) {
            return res.status(401).send('Not authenticated');
        }

        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.isAdmin) {
            res.json({ role: 'admin'});
            return res.status(200).send('Authenticated');
        } else if (decoded) {
            res.json({ role: 'user'});
            return res.status(200).send('Authenticated');
        } else {
            return res.status(401).send('Not authenticated');
        }
    } catch (err) {
        console.error('Authentication check error:', err.message);
        res.status(401).send('Not authenticated');
    }
});

const handleAPIRequest = (endpoint, apiUrlGenerator) => {
    return async (req, res) => {
        const { params } = req;
        const token = req.cookies.token; // Get the token from cookies

        if (!token) {
            return res.status(401).send('Unauthorized: No token provided');
        }

        try {
            const REQUEST_LIMIT = 20;
            const { outOfRequests, userId } = await verifyTokenAndFetchUser(token, REQUEST_LIMIT);

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
    '/v1/summary-info/:ticker',
    handleAPIRequest('summary-info', (params) => `${apiUrl}summary-info?ticker=${params.ticker}`)
);

app.get(
    '/v1/predict/:symbol',
    handleAPIRequest('predict', (params) => `${apiUrl}predict?symbol=${params.symbol}`)
);
app.get(
    '/v1/rsi/:ticker',
    handleAPIRequest('summary-info', (params) => `${apiUrl}rsi?ticker=${params.ticker}`)
);

async function getUserRequests(userId) {
    conn = await pool.getConnection();

    // Fetch the total API consumption for the user
    const requests = await conn.query(`
        SELECT COUNT(r.id) 
        FROM users u 
        LEFT JOIN requests r ON u.id = r.user_id
        WHERE u.id = ?;`, [userId]);

    return Number(requests[0]['COUNT(r.id)']);
}

// External API Logic
const verifyTokenAndFetchUser = async (token, REQUEST_LIMIT) => {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.userId;

    let outOfRequests = false;

    requests = await getUserRequests(userId);

    // Check if the user has exceeded the request limit
    outOfRequests = requests >= REQUEST_LIMIT;


    return { outOfRequests, userId };
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

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});