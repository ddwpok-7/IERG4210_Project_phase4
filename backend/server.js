const express = require('express');
const app = express();
const mysql = require('mysql2');
const cors = require('cors');
const multer = require('multer');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const sanitizeHtml = require('sanitize-html');
const csurf = require('csurf');
const port = 3000;

const origin = 'http://localhost:3001';

app.use(cors({
    origin: origin,
    credentials: true,
}));

console.log(`CORS configured for origin: ${origin} with credentials`);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.json());

// CSP Header to mitigate XSS
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; object-src 'none'");
    next();
});

// CSRF Protection
const csrfProtection = csurf({ cookie: { httpOnly: true, secure: false, sameSite: 'Strict' } }); // secure: true with SSL

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Aa246810@',  //Database password
    database: 'ierg4210'    //Database name
});

db.connect(err => {
    if (err) {
        console.error('Database connection failed:', err.stack);
        return;
    }
    console.log('Connected to database.');
});

const uploadpath = "../html/uploads";
const storage = multer.diskStorage({
    destination: uploadpath,
    filename: (req, file, cb) => {
        cb(null, Date.now() + file.originalname);
    }
});

const upload = multer({ storage: storage });
app.use(express.static(uploadpath));

// CSRF Token Route
app.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

function checkAdmin(req,res,next){
    const sessionToken = req.cookies.authToken;
    db.query('select is_admin from users WHERE session_token = ?', [ sessionToken],
        (err, results)=>{
            console.log(results);
            if (err || results.length === 0) {
                return ;
            }
            if (results[0].is_admin===1){
                next();
            } else {
                res.redirect('/');
                return;
            }
        }
    );

    
}

app.post('/adminAddCategory', checkAdmin, csrfProtection, (req, res) => {
    const { name } = req.body;

    const sanitizedName = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });

    if (!sanitizedName) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const sql = 'INSERT INTO categories ( name ) VALUES (?)';
    db.query(sql, [sanitizedName], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        console.log('Category added successfully!');
        res.end('Category added successfully!');
    });
});

app.post('/adminAddProduct', checkAdmin, upload.single('image1'), csrfProtection, (req, res) => {
    const { catid, name, price, description } = req.body;
    const imageUrl = req.file ? req.file.filename : null;

    console.log(imageUrl);

    const sanitizedName = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });
    const sanitizedDescription = sanitizeHtml(description, { allowedTags: [], allowedAttributes: {} });
    const sanitizedCatid = parseInt(catid, 10);
    const sanitizedPrice = parseFloat(price);

    if (!sanitizedName || isNaN(sanitizedCatid) || isNaN(sanitizedPrice) || sanitizedPrice < 0) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const sql = 'INSERT INTO products (catid, name, price, description, image_url) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [sanitizedCatid, sanitizedName, sanitizedPrice, sanitizedDescription, imageUrl], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        console.log('Product added successfully!');
        res.end('Product added successfully!');
    });
});

app.post('/adminUpdateProduct', checkAdmin, upload.single('image2'), csrfProtection, (req, res) => {
    const { pid, name, price, description } = req.body;
    const imageUrl = req.file ? req.file.filename : null;

    const sanitizedPid = parseInt(pid, 10);
    const sanitizedName = sanitizeHtml(name, { allowedTags: [], allowedAttributes: {} });
    const sanitizedDescription = sanitizeHtml(description, { allowedTags: [], allowedAttributes: {} });
    const sanitizedPrice = parseFloat(price);

    if (isNaN(sanitizedPid) || !sanitizedName || isNaN(sanitizedPrice) || sanitizedPrice < 0) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    const sql = 'UPDATE products SET name=?, price=?, description=?, image_url=? WHERE pid=?';
    db.query(sql, [sanitizedName, sanitizedPrice, sanitizedDescription, imageUrl, sanitizedPid], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        console.log('Product updated successfully!');
        res.end('Product updated successfully!');
    });
});

app.post('/adminDeleteProduct', checkAdmin, csrfProtection, (req, res) => {
    const { pid } = req.body;
    const sanitizedPid = parseInt(pid, 10);

    if (isNaN(sanitizedPid)) {
        return res.status(400).json({ error: 'Invalid product ID' });
    }

    db.query('DELETE FROM products WHERE pid=?', [sanitizedPid], (err) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        console.log('Product deleted successfully!');
        res.end(`Product with ID ${sanitizedPid} deleted successfully.`);
    });
});

app.get('/', (req, res) => {
    db.query('SELECT * FROM categories', (err, categories) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(categories);
    });
});

app.get('/productList', (req, res) => {
    db.query('SELECT * FROM products', (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

app.get('/categories', (req, res) => {
    const catid = parseInt(req.query.catid, 10);
    
    if (isNaN(catid)) return res.status(400).json({ error: 'Invalid category ID' });

    db.query('SELECT * FROM categories WHERE catid = ?', [catid], (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

app.get('/productPath', (req, res) => {
    const pid = parseInt(req.query.pid, 10);

    if (isNaN(pid)) return res.status(400).json({ error: 'Invalid product ID' });

    db.query('SELECT * FROM products WHERE pid = ?', [pid], (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

app.get('/products', (req, res) => {
    const catid = parseInt(req.query.catid, 10);

    if (isNaN(catid)) return res.status(400).json({ error: 'Invalid category ID' });

    db.query('SELECT * FROM products WHERE catid = ?', [catid], (err, products) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(products);
    });
});

app.get('/productInformation', (req, res) => {
    const pid = parseInt(req.query.pid, 10);

    if (isNaN(pid)) return res.status(400).json({ error: 'Invalid product ID' });

    db.query('SELECT * FROM products WHERE pid = ?', [pid], (err, product) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (product.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(product);
    });
});

app.get('/navigationcategoryPath', (req, res) => {
    const catid = parseInt(req.query.catid, 10);

    if (isNaN(catid)) return res.status(400).json({ error: 'Invalid category ID' });

    db.query('SELECT * FROM categories WHERE catid = ?', [catid], (err, category) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(category);
    });
});

app.get('/getProductDetails', (req, res) => {
    const pid = parseInt(req.query.pid, 10);

    if (isNaN(pid)) return res.status(400).json({ error: 'Invalid product ID' });

    const sql = 'SELECT name, price FROM products WHERE pid = ?';
    db.query(sql, [pid], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('Product not found');
        }
        res.json(results[0]);
    });
});


// Middleware to check authentication
const authenticate = (req, res, next) => {
    const token = req.cookies.authToken;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
  
    db.query('SELECT * FROM users WHERE session_token = ?', [token], (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ error: 'Invalid token' });
      }
      req.user = results[0];
      next();
    });
  };
  
// Login route
app.post('/login', csrfProtection, async (req, res) => {
    const { email, password, _csrf } = req.body;

    const sanitizedEmail = sanitizeHtml(email, { allowedTags: [], allowedAttributes: {} });

    if (!sanitizedEmail || !password) return res.status(400).json({ error: 'Invalid input' });

    db.query('SELECT * FROM users WHERE email = ?', [sanitizedEmail], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const sessionToken = require('crypto').randomBytes(16).toString('hex');
        db.query('UPDATE users SET session_token = ? WHERE userid = ?', [sessionToken, user.userid]);

        res.cookie('authToken', sessionToken, {
            httpOnly: true,
            secure: false,
            maxAge: 2 * 24 * 60 * 60 * 1000,
            sameSite: 'Strict',
            path: '/',
        });

        console.log('Login successfully! Setting Cookie: authToken=', sessionToken);
        res.json({ isAdmin: user.is_admin === 1, email: user.email });
    });
});

// Check auth status
app.get('/check-auth', (req, res) => {
    console.log('Check-auth - Received Cookie:', req.cookies.authToken);
    
    const token = req.cookies.authToken;
    if (!token) {
        return res.json({ authenticated: false });
    }

    db.query('SELECT * FROM users WHERE session_token = ?', [token], (err, results) => {
        if (err || results.length === 0) {
            return res.json({ authenticated: false });
        }
        const user = results[0];
        res.json({ authenticated: true, isAdmin: user.is_admin === 1, email: user.email });
    });
});

// Logout route
app.post('/logout', csrfProtection, (req, res) => {
    const token = req.cookies.authToken;
    if (token) {
        db.query('UPDATE users SET session_token = NULL WHERE session_token = ?', [token]);
    }
    res.clearCookie('authToken');
    res.sendStatus(200);
});

// Change password route
app.post('/change-password', authenticate, csrfProtection, async (req, res) => {
    const { currentPassword, newPassword, _csrf } = req.body;
    const user = req.user;

    // Validate current password
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match) {
        return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear session token
    db.query(
        'UPDATE users SET password = ?, session_token = NULL WHERE userid = ?',
        [hashedNewPassword, user.userid],
        (err) => {
            if (err) {
                console.error('Error updating password:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.clearCookie('authToken');
            res.json({ message: 'Password changed successfully' });
        }
    );
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});