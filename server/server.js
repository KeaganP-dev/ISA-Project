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

const swaggerUi = require('swagger-ui-express');
const swaggerDocs = require('./swaggerConfig.js');

app.use(cors({
    origin: 'https://isa-project-client.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'Set-Cookie'],
}));

// Middlewares
app.use(bodyParser.json());
app.use(cookieParser());
app.use('/v1/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// MariaDB connection pool
const pool = mariadb.createPool({
    host: '127.0.0.1',
    user: 'appuser',
    password: 'password',
    database: 'userAuth',
    connectionLimit: 5
});

app.options('*', cors());

// Helper function to normalize paths
const normalizePath = (path) => {
    // Replace dynamic segments (e.g., user IDs, UUIDs, or slugs) with a placeholder
    return path.replace(/\/(users|summary-info|predict|rsi)\/[^\s/]+$/, '/$1/:id');
};

// Middleware to normalize and log endpoint calls
app.use((req, res, next) => {
    const normalizedPath = normalizePath(req.path); // Normalize the path
    console.log(`Endpoint called: ${req.method} ${normalizedPath}`);
    req.normalizedPath = normalizedPath; // Attach normalized path to `req` for later use
    next(); // Pass control to the next middleware
});

// Middleware to log requests in the database
app.use(async (req, res, next) => {
    const token = req.cookies?.token; // Safely access cookies
    let user = null;

    // Decode JWT token to extract user ID
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET); // Ensure JWT_SECRET is defined
            user = decoded.userId;
        } catch (jwtError) {
            console.warn('Invalid or expired token:', jwtError.message);
        }
    }

    if (!user || !req.normalizedPath) {
        return next(); // Skip logging if no user ID or normalized path
    }

    let conn;
    try {
        conn = await pool.getConnection(); // Establish a connection to the database

        // Check if the endpoint already exists
        const [existingEndpoint] = await conn.query(
            'SELECT id FROM endpoints WHERE endpoint = ? AND method = ?',
            [req.normalizedPath, req.method]
        );

        let endpointId;
        if (existingEndpoint) {
            endpointId = existingEndpoint.id; // Use the existing endpoint ID
        } else {
            // Insert a new endpoint if not found
            const result = await conn.query(
                'INSERT INTO endpoints (endpoint, method) VALUES (?, ?)',
                [req.normalizedPath, req.method]
            );
            endpointId = result.insertId;
        }

        // Log the request
        await conn.query(
            'INSERT INTO requests (user_id, endpoint_id, timestamp) VALUES (?, ?, NOW())',
            [user, endpointId]
        );

        console.log(`Logged request: User ${user}, Endpoint ${req.normalizedPath}`);
    } catch (err) {
        console.error('Error logging request:', err.message);
    } finally {
        if (conn) conn.release(); // Always release the connection back to the pool
    }

    next(); // Pass control to the next middleware
});


/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Create a new user with first name, email, and password.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - email
 *               - password
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: John
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john.doe@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: StrongP@ssw0rd
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: All fields are required or user already exists
 *       500:
 *         description: Server error
 */

// register endpoint
app.post('/v1/register', async (req, res) => {
    const { firstName, email, password } = req.body;
    if (!firstName || !email || !password) return res.status(400).send('All fields are required');

    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

    if (!emailRegex.test(email)) {
        return; // Stop the function if the email is invalid
    }

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


/**
 * @swagger
 * /login:
 *   post:
 *     summary: Log in a user
 *     description: Authenticate a user using email and password. Returns a session token upon successful authentication.
 *     tags:
 *       - Authentication
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The user's email address
 *                 example: john.doe@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 description: The user's password
 *                 example: myStrongPassword123
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Login successful
 *       400:
 *         description: Invalid email or password, or missing required fields
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: All fields are required
 *       500:
 *         description: Server error
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Server error
 */
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

/**
 * @swagger
 * /users/{email}:
 *   put:
 *     summary: Update user details (Admin only)
 *     description: Allows an admin to update the email address of an existing user.
 *     tags:
 *       - Admin
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *         description: The current email of the user to update.
 *         example: old.email@example.com
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newEmail:
 *                 type: string
 *                 format: email
 *                 description: The new email address for the user.
 *                 example: new.email@example.com
 *     responses:
 *       200:
 *         description: User updated successfully.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "User updated successfully"
 *       400:
 *         description: Invalid request or missing required fields.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Invalid request. Provide new email."
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Forbidden - Admin privileges required or invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Forbidden: Admins only"
 *       404:
 *         description: User not found.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "User not found"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Server error"
 */

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
                const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

                if (!emailRegex.test(newEmail)) {
                    return; // Stop the function if the email is invalid
                }

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

/**
 * @swagger
 * /users/{email}:
 *   delete:
 *     summary: Delete a user (Admin only)
 *     description: Allows an admin to delete a user by their email address.
 *     tags:
 *       - Admin
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *         description: The email of the user to delete.
 *         example: user.email@example.com
 *     responses:
 *       200:
 *         description: User deleted successfully.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "User deleted successfully"
 *       400:
 *         description: Missing required email field.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Email is required"
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Forbidden - Admin privileges required or invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Forbidden: Admins only"
 *       404:
 *         description: User not found.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "User not found"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Server error"
 */

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

/**
 * @swagger
 * /api-consumption:
 *   get:
 *     summary: Get user's API consumption
 *     description: Retrieve the total number of API requests made by the authenticated user.
 *     tags:
 *       - Usage
 *     responses:
 *       200:
 *         description: Total API requests returned for the authenticated user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalRequests:
 *                   type: integer
 *                   description: Total number of API requests made by the user.
 *                   example: 42
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Invalid token"
 *       500:
 *         description: Internal server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal server error"
 */

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

/**
 * @swagger
 * /endpoint-requests:
 *   get:
 *     summary: Get total requests per endpoint (Admin only)
 *     description: Retrieve the total number of API requests made to each endpoint.
 *     tags:
 *       - Admin
 *     responses:
 *       200:
 *         description: Total requests per endpoint returned.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   method:
 *                     type: string
 *                     description: HTTP method of the endpoint.
 *                     example: GET
 *                   endpoint:
 *                     type: string
 *                     description: The endpoint path.
 *                     example: /v1/login
 *                   total_requests:
 *                     type: integer
 *                     description: Total number of requests made to the endpoint.
 *                     example: 120
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Forbidden - Admin privileges required or invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Forbidden: Admins only"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Server error"
 */

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

/**
 * @swagger
 * /user-requests:
 *   get:
 *     summary: Get total requests per user (Admin only)
 *     description: Retrieve the total number of API requests made by each user.
 *     tags:
 *       - Admin
 *     responses:
 *       200:
 *         description: Total requests per user returned.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   user_name:
 *                     type: string
 *                     description: The name of the user.
 *                     example: John Doe
 *                   email:
 *                     type: string
 *                     description: The email address of the user.
 *                     example: john.doe@example.com
 *                   total_requests:
 *                     type: integer
 *                     description: Total number of API requests made by the user.
 *                     example: 85
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Forbidden - Admin privileges required or invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Forbidden: Admins only"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Server error"
 */

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


/**
 * @swagger
 * /auth-check:
 *   get:
 *     summary: Check if the user is authenticated
 *     description: Verifies if the user is authenticated by checking their session token. Returns the user's role (admin or user) if authenticated.
 *     tags:
 *       - Authentication
 *     responses:
 *       200:
 *         description: User is authenticated.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 role:
 *                   type: string
 *                   description: The role of the authenticated user.
 *                   example: admin
 *       401:
 *         description: Not authenticated.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: Not authenticated
 */
// Endpoint: Check if the user is authenticated
app.get('/v1/auth-check', (req, res) => {
    const token = req.cookies.token; // Assuming you're using cookies for authentication
    console.log('endpoint auth-check called');

    try {
        if (!token) {
            console.log("no token");
            return res.status(401).send('Not authenticated');
        }
        console.log("there is a token");

        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.isAdmin) {
            console.log("admin");
            return res.json({ role: 'admin' }); // Send admin role
        } else if (decoded) {
            console.log("user");
            return res.json({ role: 'user' }); // Send user role
        } else {
            console.log("not authenticated");
            return res.status(401).send('Not authenticated');
        }
    } catch (err) {
        console.error('Authentication check error:', err.message);
        return res.status(401).send('Not authenticated');
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

// Validation middleware
function validateInput(req, res, next) {
    const regex = /^[a-zA-Z0-9]{1,4}$/;
    const { ticker, symbol } = req.params;

    // Check if ticker or symbol is provided and matches the regex
    if (ticker && !regex.test(ticker)) {
        return res.status(400).json({ error: 'Invalid ticker format. It should be 1-4 alphanumeric characters.' });
    }

    if (symbol && !regex.test(symbol)) {
        return res.status(400).json({ error: 'Invalid symbol format. It should be 1-4 alphanumeric characters.' });
    }

    next(); // Proceed if validation passes
}

/**
 * @swagger
 * /summary-info/{ticker}:
 *   get:
 *     summary: Get summary information for a ticker
 *     description: Fetches summary information for a specific stock ticker.
 *     tags:
 *       - External API
 *     parameters:
 *       - in: path
 *         name: ticker
 *         required: true
 *         schema:
 *           type: string
 *         description: The stock ticker symbol (e.g., AAPL).
 *         example: AAPL
 *     responses:
 *       200:
 *         description: Summary information returned successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 name:
 *                   type: string
 *                   description: Name of the stock.
 *                   example: Apple Inc.
 *                 price:
 *                   type: number
 *                   description: Current stock price.
 *                   example: 150.23
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Invalid token"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal server error"
 */

// Route for summary-info with ticker validation
app.get(
    '/v1/summary-info/:ticker',
    validateInput, // Apply validation middleware here
    handleAPIRequest('summary-info', (params) => `${apiUrl}summary-info?ticker=${params.ticker}`)
);

/**
 * @swagger
 * /predict/{symbol}:
 *   get:
 *     summary: Predict stock performance
 *     description: Fetches a prediction for a specific stock symbol based on historical data.
 *     tags:
 *       - External API
 *     parameters:
 *       - in: path
 *         name: symbol
 *         required: true
 *         schema:
 *           type: string
 *         description: The stock symbol to predict (e.g., TSLA).
 *         example: TSLA
 *     responses:
 *       200:
 *         description: Stock prediction returned successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 symbol:
 *                   type: string
 *                   description: The stock symbol.
 *                   example: TSLA
 *                 prediction:
 *                   type: number
 *                   description: Predicted stock price.
 *                   example: 1200.50
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Invalid token"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal server error"
 */

// Route for predict with symbol validation
app.get(
    '/v1/predict/:symbol',
    validateInput, // Apply validation middleware here
    handleAPIRequest('predict', (params) => `${apiUrl}predict?symbol=${params.symbol}`)
);

/**
 * @swagger
 * /rsi/{ticker}:
 *   get:
 *     summary: Fetch RSI for a ticker
 *     description: Retrieves the Relative Strength Index (RSI) for a specific stock ticker.
 *     tags:
 *       - External API
 *     parameters:
 *       - in: path
 *         name: ticker
 *         required: true
 *         schema:
 *           type: string
 *         description: The stock ticker symbol (e.g., MSFT).
 *         example: MSFT
 *     responses:
 *       200:
 *         description: RSI data returned successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ticker:
 *                   type: string
 *                   description: The stock ticker symbol.
 *                   example: MSFT
 *                 rsi:
 *                   type: number
 *                   description: The Relative Strength Index (RSI) value.
 *                   example: 70.12
 *       401:
 *         description: Unauthorized - No token provided.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Unauthorized: No token provided"
 *       403:
 *         description: Invalid token.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Invalid token"
 *       500:
 *         description: Server error.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "Internal server error"
 */

// Route for RSI with ticker validation
app.get(
    '/v1/rsi/:ticker',
    validateInput, // Apply validation middleware here
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