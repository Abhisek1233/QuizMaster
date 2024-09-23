// Import necessary modules
const express = require('express');
const app = express();
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

// Async IIFE to handle connection setup
(async () => {
    try {
        // Database connection pool
        const connection = await mysql.createPool({
            host: "localhost",
            user: "root",
            database: "quize_app",
            password: "Abhisek@2004",
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });

        // Set view engine to EJS
        app.set('view engine', 'ejs');
        app.set('views', path.join(__dirname, 'views'));

        // Middleware to parse request body
        app.use(bodyParser.urlencoded({ extended: true }));
        app.use(express.static('public'));

        // Setup session
        app.use(session({
            secret: 'your_secret_key',
            resave: false,
            saveUninitialized: true,
        }));

        // GET route for signup page
        app.get('/signup', (req, res) => {
            res.render('signup');
        });

        // POST route for signup
        // POST route for signup
app.post('/signup', async (req, res) => {
    const { username, email, password, cpassword } = req.body;

    if (!username || !email || !password || !cpassword) {
        return res.send('All fields are required');
    }

    if (password !== cpassword) {
        return res.send('Passwords do not match');
    }

    try {
        // Check if the username or email already exists
        const [existingUser] = await connection.query('SELECT username, email FROM users WHERE username = ? OR email = ?', [username, email]);
        if (existingUser.length > 0) {
            return res.send('Username or email already exists. Please choose a different one.');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into database
        await connection.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword]);

        // Redirect to login page after successful signup
        res.redirect('/login');
    } catch (err) {
        console.error('Error during signup:', err);
        res.status(500).send('An error occurred during signup. Please try again later.');
    }
});


        // GET route for login page
        app.get('/login', (req, res) => {
            res.render('login');
        });

        // POST route for login
        // POST route for login
app.post('/login', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.send('Username, email, and password are required');
    }

    try {
        // Find the user in the database
        const [user] = await connection.query('SELECT * FROM users WHERE username = ? AND email = ?', [username, email]);

        if (user.length === 0) {
            return res.send('Invalid username, email, or password');
        }

        // Compare the provided password with the hashed password in the database
        const passwordMatch = await bcrypt.compare(password, user[0].password);

        if (!passwordMatch) {
            return res.send('Invalid username, email, or password');
        }

        // Set session and redirect to home page
        req.session.username = user[0].username;
        res.redirect('/home');
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('An error occurred during login. Please try again later.');
    }
});

        // GET route for home page
        app.get('/', (req, res) => {
            if (!req.session.username) {
                return res.redirect('/login');
            }

            // Pass the session username (applicantName) to the view
            res.render('home', { applicantName: req.session.username });
        });

        // GET route for home page
        app.get('/home', (req, res) => {
            if (!req.session.username) {
                return res.redirect('/login');
            }

            // Pass the session username (applicantName) to the view
            res.render('home', { applicantName: req.session.username });
        });

        // Logout route
        app.get('/logout', (req, res) => {
            req.session.destroy(() => {
                res.redirect('/login');
            });
        });

        // GET route for forgot password page
    app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

// POST route to handle password reset request
app.post('/reset-password', async (req, res) => {
    const { username, id } = req.body;

    if (!username || !id) {
        return res.send('Both username and ID are required');
    }

    try {
        // Check if the username and ID match a record in the database
        const [user] = await connection.query('SELECT * FROM users WHERE username = ? AND id = ?', [username, id]);

        if (user.length === 0) {
            return res.send('Invalid username or ID');
        }

        // If valid, render a form for the user to set a new password
        // Assuming you fetch email from the user record
        const email = user[0].email;
        res.render('reset-password', { username, email });
    } catch (err) {
        console.error('Error during reset password verification:', err);
        res.status(500).send('An error occurred. Please try again later.');
    }
});



// POST route to handle the password update
// POST route to handle the password update
app.post('/update-password', async (req, res) => {
    const { username, email, newPassword, confirmPassword } = req.body;

    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
        return res.send('Passwords do not match or are missing');
    }

    try {
        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password and email in the database
        await connection.query('UPDATE users SET password = ?, email = ? WHERE username = ?', [hashedPassword, email, username]);

        // Render a success message view
        res.render('password-success');  // Make sure this view exists and provides feedback to the user

    } catch (err) {
        console.error('Error during password update:', err);
        res.status(500).send('An error occurred. Please try again later.');
    }
});


app.post('/submit-quiz', async (req, res) => {
    if (!req.session.username) {
        return res.redirect('/login');
    }

    const { subject, score, totalQuestions } = req.body;

    // Get user_id based on session username
    const [user] = await connection.query('SELECT id FROM users WHERE username = ?', [req.session.username]);
    const userId = user.length > 0 ? user[0].id : null;

    if (!userId) {
        return res.status(400).send('User not found.');
    }

    try {
        // Insert quiz results into the database
        await connection.query('INSERT INTO quiz_results (user_id, subject, score, total_questions) VALUES (?, ?, ?, ?)', [userId, subject, score, totalQuestions]);

        res.send('Quiz results submitted successfully!');
    } catch (err) {
        console.error('Error during quiz result insertion:', err);
        res.status(500).send('An error occurred while submitting the quiz. Please try again later.');
    }
});



        // Start the server
        app.listen(3000, () => {
            console.log('Server is running on http://localhost:3000');
        });

    } catch (err) {
        console.error('Error during database connection setup:', err);
    }
})();




