const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const nodemailer = require('nodemailer'); // Add this line at the top of your file
const crypto = require('crypto'); // Add this line at the top of your file
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const cors = require('cors');

const app = express();
// cors

app.use(cors());

// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
    secret: 'your-secret-key', // Replace with a random string
    resave: true,
    saveUninitialized: true
}));

// MySQL connection setup
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Replace with your MySQL username
    password: '', // Replace with your MySQL password
    database: 'data_users'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL Database.');
});

// Signup route (GET and POST)
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.post('/signup', (req, res) => {
    const { username, password, email } = req.body; // Include email in the destructured object
    const hashedPassword = bcrypt.hashSync(password, 8);
    const role = 'user'; // Default role for new users

    // Check if the username already exists
    const checkQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkQuery, [username], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            // Username exists
            res.send('<script>alert("Account already exists. Please choose a different username."); window.location.href = "/signup";</script>');
        } else {
            // Register new user
            const insertQuery = 'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)';
            db.query(insertQuery, [username, hashedPassword, email, role], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.send('An unexpected error occurred. Please try again.'); // User-friendly message
                }
                res.send('<script>alert("Registered successfully!"); window.location.href = "/login";</script>');
            });
        }
    });
});


// Login route (GET and POST)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html')); // Use path.join for consistency
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    console.log('Login attempt:', { username }); // Log the username for debugging

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error('Database Error:', err); // Log any database errors
            return res.status(500).send('Internal server error.');
        }

        if (results.length > 0) {
            const user = results[0];

            // Check if the user's status is 'suspended'
            if (user.status === 'suspended') {
                return res.send('<script>alert("Your account is suspended. Please contact support."); window.location.href = "/login";</script>');
            }

            const isValidPassword = bcrypt.compareSync(password, user.password);

            console.log('Password valid:', isValidPassword); // Log if password is valid

            if (isValidPassword) {
                req.session.user = user; // Store user information in session
                console.log('User logged in:', user); // Log user information upon successful login
                
                // Redirect based on role
                if (user.role === 'admin') {
                    res.redirect('/admin');
                } else {
                    req.session.userId = user.id;
                    res.redirect('/us_dash');
                }
            } else {
                console.log('Incorrect Password for user:', username); // Log incorrect password attempt
                res.send('<script>alert("Incorrect Password."); window.location.href = "/login";</script>');
            }
        } else {
            console.log('User not found:', username); // Log user not found
            res.send('User not found!');
        }
    });
});


// Route to serve admin creation form (GET)
app.get('/create_admin', (req, res) => {
    console.log('Session user:', req.session.user); // Log session user
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'create_admin.html')); 
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});


// Create Admin (POST)
app.post('/create_admin', (req, res) => {
    const { username, password, email } = req.body; // Include email in the destructured object
    const hashedPassword = bcrypt.hashSync(password, 8);
    const role = 'admin'; // Default role for new admins

    // Check if the username already exists
    const checkQuery = 'SELECT * FROM users WHERE username = ?';
    db.query(checkQuery, [username], (err, results) => {
        if (err) throw err;

        if (results.length > 0) {
            // Username exists
            res.send('<script>alert("Account already exists. Please choose a different username."); window.location.href = "/create_admin";</script>');
        } else {
            // Register new admin
            const insertQuery = 'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)';
            db.query(insertQuery, [username, hashedPassword, email, role], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.send('An unexpected error occurred. Please try again.'); // User-friendly message
                }
                res.send('<script>alert("Admin registered successfully!"); window.location.href = "/admin_login";</script>');
            });
        }
    });
});


// Admin Page Route
app.get('/admin', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'admin_home.html'));
    } else {
        res.send('Access Denied');
    }
});

// Route to serve the Manage Panel Admin page (GET)
app.get('/manage_panel_admin', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'manage_panel_admin.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});


// Route to serve the Pending page (GET)
app.get('/pending_panel_admin', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'pending_panel_admin.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});

// User Page Route
app.get('/user', (req, res) => {
    if (req.session.user && req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'user_home.html'));
    } else {
        res.send('Access Denied');
    }
});

// Route to serve the Pending page (GET)
app.get('/article_user', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'article_user.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/article_user";</script>'); // Alert for access denied
    }
});

// Route to serve the Create Admin (GET)
app.get('/create_admin', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'create_admin.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});


// Route to serve the Admin Settings (GET)
app.get('/admin_settings', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'admin_settings.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});

//----------------------------------------------------------------------------


const isAdmin = (req, res, next) => {
    if (req.session.user && req.session.user.role === 'admin') {
        return next(); // User is admin, proceed to the next middleware/route
    }
    res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>');
};

// Route to manage users (GET)
app.get('/admin/manage_users', isAdmin, (req, res) => {
    const query = 'SELECT id, username, email, role, status FROM users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).json({ message: 'An error occurred while fetching users.' });
        }
        res.json(results); // Return user data as JSON
    });
});

// Route to edit user (POST)
app.post('/edit_user/:id', isAdmin, (req, res) => {
    const { id } = req.params;
    const { username, email, role, status } = req.body;

    const updateQuery = 'UPDATE users SET username = ?, email = ?, role = ?, status = ? WHERE id = ?';
    db.query(updateQuery, [username, email, role, status, id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'An error occurred while updating the user.' });
        }
        res.status(200).json({ message: 'User updated successfully!' });
    });
});

// Route to delete user (DELETE)
app.delete('/delete_user/:id', isAdmin, (req, res) => {
    const { id } = req.params;

    const deleteQuery = 'DELETE FROM users WHERE id = ?';
    db.query(deleteQuery, [id], (err, result) => {
        if (err) {
            console.error('Error deleting user:', err);
            return res.status(500).send('An error occurred while deleting the user.');
        }
        if (result.affectedRows === 0) {
            return res.status(404).send('User not found.');
        }
        res.status(200).send('User Deleted Successfully.');
    });
});

// Route to toggle user status (POST)
app.post('/admin/toggle_user_status/:id', isAdmin, (req, res) => {
    const { id } = req.params;

    const checkQuery = 'SELECT status FROM users WHERE id = ?';
    db.query(checkQuery, [id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'An error occurred while checking user status.' });
        }
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Determine the new status
        console.log(`Current status: ${results[0].status}`); // Log current status
        const newStatus = results[0].status === 'active' ? 'suspended' : 'active';
        console.log(`New status: ${newStatus}`); // Log new status       

        const updateQuery = 'UPDATE users SET status = ? WHERE id = ?';
        db.query(updateQuery, [newStatus, id], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'An error occurred while toggling user status.' });
            }
            res.status(200).json({ message: `User status updated to ${newStatus}.` });
        });
    });
});







//----------------------------------------------------------------------------------

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) throw err;
        res.redirect('/login');
    });
});

//ADMIN SETTINGS---------------------------------------------------------------------

// Settings update route
app.use(express.urlencoded({ extended: true }));

app.post('/update_admin_settings', async (req, res) => {
    const { username, email, password } = req.body;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update the user's details in the database
    const sql = `UPDATE users SET password = ?, email = ? WHERE username = ?`;
    db.query(sql, [hashedPassword, email, username], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error updating password.');
        }
        return res.send('Password updated successfully!');
    });
});


//ADMIN SETTINGS---------------------------------------------------------------------

// CSS CODES ------------------------------------------------------------------------
app.use('/css', express.static(path.join(__dirname, 'css'))); // Ensure this matches your directory structure

// CSS CODES ------------------------------------------------------------------------


// USER DASH BOARD JAVA SCRIPT ==================================================================

app.use('/js', express.static(path.join(__dirname, 'js'))); 

// USER DASH BOARD JAVA SCRIPT ==================================================================

//Pictures---------------------------------------------------------------------------

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));

//Pictures---------------------------------------------------------------------------


// Route to serve the about us (GET)
app.get('/about_us', (req, res) => {
    res.sendFile(path.join(__dirname, '/about_us.html'));
});

// Route to serve the contact us (GET)
app.get('/contact_us', (req, res) => {
    res.sendFile(path.join(__dirname, '/contact_us.html'));
});

// Route to handle password reset request (POST)

app.post('/forgot_password', (req, res) => {
    const { email } = req.body;

    // Check if the email exists in the database
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error(err);
            return res.send('An error occurred while checking the email.');
        }

        if (results.length > 0) {
            const user = results[0];
            const token = crypto.randomBytes(20).toString('hex'); // Create a token

            // Save the token and its expiration to the database
            const expirationDate = Date.now() + 3600000; // 1 hour
            const updateQuery = 'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?';
            db.query(updateQuery, [token, expirationDate, user.id], (err) => {
                if (err) {
                    console.error(err);
                    return res.send('An error occurred while updating the token.');
                }

                // Send password reset email
                const transporter = nodemailer.createTransport({
                    service: 'Gmail', // Use your email service
                    auth: {
                        user: 'your-email@gmail.com', // Replace with your email
                        pass: 'your-email-password' // Replace with your email password
                    }
                });

                const resetLink = `http://localhost:3000/reset-password/${token}`;
                const mailOptions = {
                    from: 'julliusmartinez@gmail.com',
                    to: email,
                    subject: 'Password Reset Request',
                    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                          `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                          `${resetLink}\n\n` +
                          `If you did not request this, please ignore this email and your password will remain unchanged.`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error(error);
                        return res.send('<script>alert("Error Sending Email."); window.location.href = "/forgot_password";</script>');
                    }
                    res.send('Password reset link sent to your email address.');
                });
            });
        } else {
            res.send('No account found with that email address.');
        }
    });
});

// Route to serve the reset password page (GET)
app.get('/reset-password/:token', (req, res) => {
    const token = req.params.token;
    // Check if the token is valid and not expired
    const query = 'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?';
    db.query(query, [token, Date.now()], (err, results) => {
        if (err) {
            console.error(err);
            return res.send('An error occurred while validating the token.');
        }

        if (results.length > 0) {
            // Token is valid, serve the reset password form
            res.send(`
                <form action="/reset-password/${token}" method="post">
                    <input type="password" name="newPassword" placeholder="Enter new password" required />
                    <button type="submit">Reset Password</button>
                </form>
            `);
        } else {
            res.send('Password reset token is invalid or has expired.');
        }
    });
});

// Route to handle new password submission (POST)
app.post('/forgot_password', (req, res) => {
    const { email } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('An error occurred while checking the email.');
        }

        if (results.length > 0) {
            const user = results[0];
            const token = crypto.randomBytes(20).toString('hex');
            const expirationDate = Date.now() + 3600000; // 1 hour

            const updateQuery = 'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?';
            db.query(updateQuery, [token, expirationDate, user.id], (err) => {
                if (err) {
                    console.error('Error updating token:', err);
                    return res.status(500).send('An error occurred while updating the token.');
                }

                const transporter = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_PASS
                    }
                });

                const resetLink = `http://localhost:3000/reset-password/${token}`;
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Password Reset Request',
                    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                          `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                          `${resetLink}\n\n` +
                          `If you did not request this, please ignore this email and your password will remain unchanged.`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending email:', error);
                        return res.status(500).send('Error sending email. Please try again later.');
                    }
                    res.send('Password reset link sent to your email address.');
                });
            });
        } else {
            res.send('No account found with that email address.');
        }
    });
});

app.get('/forgot_password', (req, res) => {
    res.sendFile(path.join(__dirname, 'forgot_password.html'));
});


// Define the route to serve the Forgot Password page
app.get('/forgot_password', (req, res) => {
    // Send the Forgot Password HTML file
    res.sendFile(path.join(__dirname, 'forgot_password.html'));
});

// Admin to User Article Page =============================================


// Define the uploads directory path
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true }); // Create uploads directory
}

// Set up multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir); // Use the uploads directory
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
        cb(null, uniqueName); // Set the unique filename
    }
});

const router = express.Router();

// Configure Multer with storage
const upload = multer({ storage: storage });

app.use('/uploads', express.static('uploads'));

app.use(express.json()); 

app.get('/ad_po', (req, res) => {
    // Check if the user is logged in and is an admin
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, '/ad_post.html'));
    } else {
        // Alert for access denied and redirect to login
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>');
    }
});

app.get('/us_po', (req, res) => {
    res.sendFile(path.join(__dirname, '/us_home.html'));
});

// Route to handle post submission with file uploads
app.post('/api/posts', upload.fields([{ name: 'images', maxCount: 10 }, { name: 'video', maxCount: 1 }]), (req, res) => {
    const { title, content, section } = req.body;

    const images = req.files.images ? req.files.images : [];
    const video = req.files.video ? req.files.video[0] : null;

    // Log received data
    console.log('Received Data:', { title, content, section, images, video });
    
    // Log files received
    console.log('Files received:', req.files);

    // Optional: Check if title, content, and section are provided
    if (!title || !content || !section) {
        console.error('Missing required fields');
        return res.status(400).send('Please provide a title, content, and section.');
    }

    // Save post data in the database
    const sql = 'INSERT INTO posting (title, content, section, images, video) VALUES (?, ?, ?, ?, ?)';
    const imagePaths = images.length > 0 ? images.map(img => `uploads/${img.filename}`).join(',') : null;
    const videoPath = video ? `uploads/${video.filename}` : null;

    console.log('Image Paths:', imagePaths); // Log image paths
    console.log('Video Path:', videoPath); // Log video path

    db.query(sql, [title, content, section, imagePaths, videoPath], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error saving post');
        }
        res.redirect('/us_po'); // Redirect to users' home page
    });
});

// Fetch posts
app.get('/api/posts', (req, res) => {
    const sql = 'SELECT * FROM posting ORDER BY created_at DESC'; // Adjust if necessary
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error retrieving posts');
        }
        res.json(results); // Send posts as JSON
    });
});


module.exports = router;
// Admin to User Article Page =============================================


// Delete Admin Post =======================================================

app.get('/admin_manage_post', (req, res) => {
    // Check if the user is logged in and is an admin
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'admin_manage_post.html'));
    } else {
        // Alert for access denied and redirect to login
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>');
    }
});



// DELETE endpoint for removing a post
app.delete('/delete_post/:id', (req, res) => {
    const postId = req.params.id;
    const query = 'DELETE FROM posting WHERE id = ?';

    db.query(query, [postId], (error, result) => {
        if (error) {
            console.error('Error deleting post:', error);
            return res.status(500).json({ error: 'Error deleting post' });
        }

        if (result.affectedRows > 0) {
            res.status(200).json({ message: 'Post deleted successfully' });
        } else {
            res.status(404).json({ error: 'Post not found' });
        }
    });
});






// Delete Admin Post ========================================================

// User Posting Section =====================================================

// Serve user posting page
app.get('/us_home', (req, res) => {
    res.sendFile(path.join(__dirname, '/user_posting.html'));
});

// Middleware to log current session details for debugging
app.use((req, res, next) => {
    console.log('Current Session:', req.session); // Log session details
    next();
});

// Post new user post with file upload handling and session validation
app.post('/api/user_posts', upload.array('files'), (req, res) => {
    const userId = req.session.userId; // Access the user ID from session

    // Check if user is logged in
    if (!userId) {
        console.log('Unauthorized access attempt. No user ID in session.');
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const title = req.body.title;
    const description = req.body.description;
    const section = req.body.section;
    const files = req.files;

    // Log the incoming request data for debugging
    console.log("Request Body:", req.body);
    console.log(`Session User ID: ${userId}`);
    console.log(`Title: ${title}`);
    console.log(`Description: ${description}`);
    console.log(`Section: ${section}`);
    console.log(`Files:`, files);

    // Validate title, description, and section
    const validSections = ['News', 'Sports', 'Academic', 'Other'];
    if (!title || !description || !validSections.includes(section)) {
        console.log('Validation Error: Invalid title, description, or section.');
        return res.status(400).json({ success: false, message: "Title, description, and valid section are required." });
    }

    // Query to get username for the user
    const getUserQuery = 'SELECT username FROM users WHERE id = ?';
    db.query(getUserQuery, [userId], (err, userResult) => {
        if (err || userResult.length === 0) {
            console.error("Error retrieving user:", err);
            return res.status(500).json({ success: false, message: "Error retrieving user." });
        }

        const username = userResult[0].username; // Get the username

        // Prepare file path if files are uploaded
        let filePath = null;
        if (files && files.length > 0) {
            filePath = files.map(file => `/uploads/${file.filename}`).join(','); // Join file paths
        }

        // SQL query to insert new post with username and set status as 'pending'
        const sql = 'INSERT INTO user_posts (user_id, username, title, description, file_path, section, status) VALUES (?, ?, ?, ?, ?, ?, ?)';
        db.query(sql, [userId, username, title, description, filePath, section, 'pending'], (err, result) => {
            if (err) {
                console.error("Database Error:", err);
                return res.status(500).json({ success: false, message: "Error creating post." });
            }
            res.json({ success: true, message: "Post created successfully! It is pending approval." });
        });
    });
});

// Fetching posts for admin approval
app.get('/api/pending_posts', (req, res) => {
    const query = 'SELECT * FROM user_posts WHERE status = "pending" ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching pending posts:', err);
            return res.status(500).json({ message: 'Error fetching pending posts' });
        }
        res.status(200).json(results);
    });
});

// Endpoint to approve or decline posts
app.post('/api/posts/:id/approve', (req, res) => {
    const postId = req.params.id;
    const { action } = req.body; // Expecting "approve" or "decline"

    // Ensure a valid action is provided
    if (action !== 'approve' && action !== 'decline') {
        console.log('Invalid action:', action);
        return res.status(400).json({ success: false, message: 'Invalid action. Use "approve" or "decline".' });
    }

    const status = action === 'approve' ? 'approved' : 'declined';
    const updateQuery = 'UPDATE user_posts SET status = ? WHERE id = ?';
    db.query(updateQuery, [status, postId], (err, result) => {
        if (err) {
            console.error('Error updating post status:', err);
            return res.status(500).json({ success: false, message: 'Error updating post status.' });
        }
        res.json({ success: true, message: `Post has been ${status}.` });
    });
});

// Fetching posts for users (only approved)
app.get('/api/user_posts', (req, res) => {
    const query = 'SELECT * FROM user_posts WHERE status = "approved" ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching posts:', err);
            return res.status(500).json({ message: 'Error fetching posts' });
        }
        res.status(200).json(results);
    });
});

// Delete post
app.delete('/api/delete_post/:id', (req, res) => {
    const postId = req.params.id;
    const deleteQuery = 'DELETE FROM user_posts WHERE id = ?';

    db.query(deleteQuery, [postId], (err, result) => {
        if (err) {
            console.error("Error deleting post:", err);
            return res.status(500).json({ success: false, message: "Error deleting post." });
        }
        res.json({ success: true, message: "Post deleted successfully." });
    });
});

// Fetching posts for admin approval
app.get('/api/pending_posts', (req, res) => {
    const query = 'SELECT * FROM user_posts ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching posts:', err);
            return res.status(500).json({ message: 'Error fetching posts' });
        }
        res.status(200).json(results);
    });
});


app.get('/api/user_posts', (req, res) => {
    const query = 'SELECT user_id, title, description, status FROM user_posts WHERE status = "approved" ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching posts:', err);
            return res.status(500).json({ success: false, message: 'Error fetching posts' });
        }
        res.status(200).json({ success: true, posts: results });
    });
});

app.get('/api/user_posts', (req, res) => {
    console.log("Received request for approved posts");
    const query = 'SELECT user_id, title, description, status FROM user_posts WHERE status = "approved" ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching posts:', err);
            return res.status(500).json({ success: false, message: 'Error fetching posts' });
        }
        console.log("Fetched posts:", results);
        res.status(200).json({ success: true, posts: results });
    });
});




// User DashBoard     VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV

app.get('/us_settings', (req, res) => {
    res.sendFile(path.join(__dirname, 'us_settings.html')); // Correctly using __dirname
});

// Example route serving user dashboard
app.get('/us_dash', (req, res) => {
    res.sendFile(path.join(__dirname, 'us_dash.html')); // Correctly using __dirname
});

// Endpoint to get the current logged-in user's details
app.get('/api/user_info', (req, res) => {
    const userId = req.session.userId; // Retrieve the user ID from the session

    if (!userId) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // Fetch user information from the database
    const query = 'SELECT username, email FROM users WHERE id = ?';
    db.query(query, [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user info:', err);
            return res.status(500).json({ success: false, message: 'Error fetching user info' });
        }

        if (result.length > 0) {
            res.json({ success: true, user: result[0] });
        } else {
            res.status(404).json({ success: false, message: 'User not found' });
        }
    });
});





// Fetching posts for user history
app.get('/api/user_posts/history', (req, res) => {
    const userId = req.session.userId; // Assuming you're using session to get the logged-in user
    const query = 'SELECT title, description, status, created_at, file_path, video_url FROM user_posts WHERE user_id = ? ORDER BY created_at DESC';

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching user posts:', err);
            return res.status(500).json({ message: 'Error fetching user posts' });
        }
        res.status(200).json(results);
    });
});

// User Posting Section =====================================================

// ADMIN  DASHBOARD +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// Assuming you're using Express and MySQL connection is established

// Endpoint to create a new user post
app.post('/api/user_posts', upload.array('files'), (req, res) => {
    const { title, description } = req.body;
    const username = req.session.username || "Anonymous"; // Get the username from session
    const files = req.files;
    const filePaths = files.map(file => file.path).join(','); // Join file paths into a comma-separated string
    const status = 'pending'; // Set initial status to 'pending'

    // Query to save post to 'user_posts' table
    const query = `
        INSERT INTO user_posts (title, description, username, file_path, status, created_at) 
        VALUES (?, ?, ?, ?, ?, NOW())
    `;

    db.query(query, [title, description, username, filePaths, status], (err, result) => {
        if (err) {
            console.error("Error inserting post:", err);
            return res.json({ success: false, message: "Error inserting post." });
        }
        res.json({ success: true, message: "Post created successfully!" });
    });
});

// Endpoint to fetch all user posts, including declined posts
app.get('/api/user_posts', (req, res) => {
    const query = `SELECT id, username, title, status, created_at FROM user_posts WHERE status IN ('approved', 'declined')`;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching user posts:", err);
            return res.status(500).json({ success: false, message: "Error fetching user posts." });
        }
        res.json(results);
    });
});

// Endpoint to delete a post
app.delete('/api/delete_post/:id', (req, res) => {
    const postId = req.params.id;
    const query = `DELETE FROM user_posts WHERE id = ?`;

    db.query(query, [postId], (err, result) => {
        if (err) {
            console.error("Error deleting post:", err);
            return res.status(500).json({ success: false, message: "Error deleting post." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: "Post not found." });
        }
        res.json({ success: true });
    });
});



// ADMIN  DASHBOARD +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// ADMIN CHECKER
app.get('/ad_checker', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'ad_checker.html'));
    } else {
        res.send('<script>alert("Access Denied"); window.location.href = "/login";</script>'); // Alert for access denied
    }
});

// API endpoint to get pending posts
app.get('/api/pending-posts', (req, res) => {
    const sql = 'SELECT id, title FROM user_posts WHERE status = "pending"';
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        res.json(results);
    });
});

// API endpoint to get post content by ID
app.get('/api/post/:id', (req, res) => {
    const postId = req.params.id;
    const sql = 'SELECT description AS content FROM user_posts WHERE id = ?';
    db.query(sql, [postId], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).json({ error: 'Post not found' });
        }
    });
});

// API endpoint for grammar checking
app.post('/api/check-grammar', async (req, res) => {
    const textToCheck = req.body.text;
    const apiUrl = 'https://api.languagetool.org/v2/check';

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                text: textToCheck,
                language: 'en-US' // Change to desired language
            })
        });

        if (!response.ok) {
            throw new Error('Error checking grammar');
        }

        const data = await response.json();
        // Send the errors back to the client
        const errors = data.matches.map(match => ({
            start: match.offset,
            end: match.offset + match.length,
            message: match.message
        }));

        res.json(errors);
    } catch (error) {
        console.error('Error checking grammar:', error);
        res.status(500).json({ error: 'Failed to check grammar' });
    }
});


// plagiarism checker
app.post('/api/', async (req, res) => {
    const { text } = req.body;

    if (!text) {
        return res.status(400).json({ message: "No text provided" });
    }

    try {
        // Forward the request to the plagiarism checker API via Ngrok URL (Replace with permanent URL in production)
        const response = await fetch("https://3dbf-136-158-44-71.ngrok-free.app/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ text }),
        });

        // Check if the response is OK before proceeding
        if (!response.ok) {
            const errorText = await response.text(); // Get the error text from response
            console.error('Plagiarism check failed:', errorText); // Log the raw error message
            return res.status(500).json({ message: 'Plagiarism check failed', error: errorText });
        }

        // Handle the JSON response from the plagiarism checker API
        const textResponse = await response.text();  // Get the response text
        try {
            const data = JSON.parse(textResponse);  // Parse JSON response
            console.log('Plagiarism checker response:', data);  // Log for debugging
            return res.json(data);  // Send the plagiarism result back to the frontend
        } catch (error) {
            console.error('Error parsing JSON response:', error);
            return res.status(500).json({ message: "Error parsing plagiarism API response" });
        }

    } catch (error) {
        console.error("Error in plagiarism check:", error);
        return res.status(500).json({ message: "Internal error, please try again later" });
    }
});


//  END ADMIN CHECKER


// Start server
app.listen(3000, () => {
    console.log('Server started on http://localhost:3000');
});

// new==============================

app.get('/user_posting', (req, res) => {
    if (req.session.user && req.session.user.role === 'user') {
        res.sendFile(path.join(__dirname, 'user_posting.html'));
    } else {
        res.send('Access Denied');
    }
});

// landing page


// Route to fetch pending user posts
app.get('/api/pending_posts', (req, res) => {
    connection.query("SELECT title, description, category, status FROM user_posts WHERE status = 'pending'", (error, result) => {
        if (error) {
            console.error("Database error:", error);
            return res.json({ success: false, message: "Failed to fetch posts" });
        }
        res.json(result);
    });
});



// Route to create a post (user-generated posts)
app.post('/api/user_posts', (req, res) => {
    const { title, description, category, file_path, username, user_id } = req.body;

    if (!category) {
        return res.status(400).json({ success: false, message: 'Category is required' });
    }

    const query = 'INSERT INTO user_posts (user_id, title, description, category, file_path, username, status) VALUES (?, ?, ?, ?, ?, ?, ?)';
    connection.query(query, [user_id, title, description, category, file_path || null, username, 'pending'], (err, result) => {
        if (err) {
            console.error('Error inserting post:', err);
            return res.status(500).json({ success: false, message: 'Error creating post' });
        }
        res.json({ success: true, message: 'Post created successfully!' });
    });
});

// Fetch all user posts including category
app.get('/api/user_posts', (req, res) => {
    const query = 'SELECT * FROM user_posts';
    connection.query(query, (err, results) => {
        if (err) {
            console.error('Error fetching posts:', err);
            return res.status(500).json({ success: false, message: 'Error fetching posts' });
        }
        res.json(results);
    });
});

// Fetch posts by category (e.g., news, sports, academics)
app.get('/api/user_posts/category/:category', (req, res) => {
    const { category } = req.params;
    const allowedCategories = ['news', 'sports', 'academics'];  // Add more if needed

    if (!allowedCategories.includes(category)) {
        return res.status(400).json({ success: false, message: 'Invalid category' });
    }

    const query = 'SELECT * FROM user_posts WHERE category = ?';
    connection.query(query, [category], (err, results) => {
        if (err) {
            console.error('Error fetching posts by category:', err);
            return res.status(500).json({ success: false, message: 'Error fetching posts' });
        }
        res.json(results);
    });
});

// Admin approves or declines a post
app.post('/api/posts/:postId/approve', (req, res) => {
    const postId = req.params.postId;
    const action = req.body.action;

    if (action !== 'approve' && action !== 'decline') {
        return res.status(400).json({ success: false, message: 'Invalid action' });
    }

    const status = action === 'approve' ? 'Approved' : 'Declined';

    const query = "UPDATE posts SET status = ? WHERE id = ?";
    connection.query(query, [status, postId], (error, result) => {
        if (error) {
            console.error("Database error:", error);
            return res.status(500).json({ success: false, message: "Failed to update post status" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'Post not found' });
        }

        res.json({ success: true, message: 'Post status updated successfully!' });
    });
});


//wow

app.get('/Sports', (req, res) => {
    res.sendFile(path.join(__dirname, 'Sports.html')); // Correctly using __dirname
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'landing_page.html')); // Correctly using __dirname
});
