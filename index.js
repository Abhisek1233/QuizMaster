const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs'); // Ensure bcrypt is imported
const dotenv = require('dotenv');
const ejs = require('ejs');
const path = require('path');

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body parser middleware
app.use(bodyParser.urlencoded({ extended: true }));

// MySQL connection
const dbOptions = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};

let connection;
try {
    connection = mysql.createConnection(dbOptions);
} catch (err) {
    console.error('Error connecting to MySQL:', err);
}

// Session store
const sessionStore = new MySQLStore(dbOptions);

// Session middleware
app.use(session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
}));

// GET route for signup page
app.get('/signup', (req, res) => {
    res.render('signup');
});

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
        const [existingUser] = await connection.promise().query(
            'SELECT username, email FROM users WHERE username = ? OR email = ?',
            [username, email]
        );
        if (existingUser.length > 0) {
            return res.send('Username or email already exists. Please choose a different one.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        await connection.promise().query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword]
        );

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
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.send('Username and password are required');
    }

    try {
        const [user] = await connection.promise().query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (user.length === 0) {
            return res.send('Invalid username or password');
        }

        const passwordMatch = await bcrypt.compare(password, user[0].password);

        if (!passwordMatch) {
            return res.send('Invalid username or password');
        }

        req.session.username = user[0].username;
        res.redirect('/home');
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('An error occurred during login. Please try again later.');
    }
});

// GET route for home page
app.get('/home', (req, res) => {
    if (!req.session.username) {
        return res.redirect('/login');
    }

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
        const [user] = await connection.promise().query(
            'SELECT * FROM users WHERE username = ? AND id = ?',
            [username, id]
        );

        if (user.length === 0) {
            return res.send('Invalid username or ID');
        }

        const email = user[0].email;
        res.render('reset-password', { username, email });
    } catch (err) {
        console.error('Error during reset password verification:', err);
        res.status(500).send('An error occurred. Please try again later.');
    }
});

// POST route to handle the password update
app.post('/update-password', async (req, res) => {
    const { username, newPassword, confirmPassword } = req.body;

    if (!newPassword || !confirmPassword || newPassword !== confirmPassword) {
        return res.send('Passwords do not match or are missing');
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await connection.promise().query(
            'UPDATE users SET password = ? WHERE username = ?',
            [hashedPassword, username]
        );

        res.render('password-success');
    } catch (err) {
        console.error('Error during password update:', err);
        res.status(500).send('An error occurred. Please try again later.');
    }
});

// POST route for submitting quiz results
app.post('/submit-quiz', async (req, res) => {
    if (!req.session.username) {
        return res.redirect('/login');
    }

    const { subject, score, totalQuestions } = req.body;

    const [user] = await connection.promise().query(
        'SELECT id FROM users WHERE username = ?',
        [req.session.username]
    );

    const userId = user.length > 0 ? user[0].id : null;

    if (!userId) {
        return res.status(400).send('User not found.');
    }

    try {
        await connection.promise().query(
            'INSERT INTO quiz_results (user_id, subject, score, total_questions) VALUES (?, ?, ?, ?)',
            [userId, subject, score, totalQuestions]
        );

        res.send('Quiz results submitted successfully!');
    } catch (err) {
        console.error('Error during quiz result insertion:', err);
        res.status(500).send('An error occurred while submitting the quiz. Please try again later.');
    }
});

// Start the server using the environment variable for port
app.listen(3000, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
