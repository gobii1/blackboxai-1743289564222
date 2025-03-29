const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const pool = require('./db');

const app = express();
const PORT = 8000;

// Middleware
app.use(bodyParser.json());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// Serve static files
app.use(express.static(path.join(__dirname)));

// API Routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT id, name, email, role FROM users WHERE email = ? AND password = ?',
      [email, password]
    );
    if (rows.length > 0) {
      req.session.user = rows[0];
      res.json(rows[0]);
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM products');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Vendor-specific endpoints
app.get('/api/products/vendor', async (req, res) => {
  if (!req.session.user?.role === 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT * FROM products WHERE vendor_id = ?',
      [req.session.user.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  if (!req.session.user?.role === 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    // Verify product belongs to this vendor
    const [product] = await pool.query(
      'SELECT vendor_id FROM products WHERE id = ?',
      [req.params.id]
    );
    
    if (!product.length || product[0].vendor_id !== req.session.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Authentication check endpoint
app.get('/api/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(req.session.user);
});

app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const [result] = await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, password, role || 'customer']
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Product Endpoints
app.post('/api/products', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { name, description, price, image_url } = req.body;
    const [result] = await pool.query(
      'INSERT INTO products (name, description, price, vendor_id, image_url) VALUES (?, ?, ?, ?, ?)',
      [name, description, price, req.session.user.id, image_url]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Order Endpoints
app.post('/api/orders', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  try {
    const { items } = req.body;
    const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    const [orderResult] = await pool.query(
      'INSERT INTO orders (user_id, total) VALUES (?, ?)',
      [req.session.user.id, total]
    );
    
    for (const item of items) {
      await pool.query(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderResult.insertId, item.product_id, item.quantity, item.price]
      );
    }
    
    res.json({ orderId: orderResult.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Cart Endpoints
app.post('/api/cart', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not logged in' });
  }
  try {
    const { productId, quantity } = req.body;
    const [product] = await pool.query('SELECT price FROM products WHERE id = ?', [productId]);
    
    if (!product.length) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // In a real app, you'd store cart in database or session
    req.session.cart = req.session.cart || [];
    req.session.cart.push({
      product_id: productId,
      quantity,
      price: product[0].price
    });
    
    res.json({ cart: req.session.cart });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Routes for all HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/products', (req, res) => {
  res.sendFile(path.join(__dirname, 'products.html'));
});

app.get('/product-detail', (req, res) => {
  res.sendFile(path.join(__dirname, 'product-detail.html'));
});

app.get('/cart', (req, res) => {
  res.sendFile(path.join(__dirname, 'cart.html'));
});

app.get('/checkout', (req, res) => {
  res.sendFile(path.join(__dirname, 'checkout.html'));
});

app.get('/vendor-dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'vendor-dashboard.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Available routes:');
  console.log(`- Home: http://localhost:${PORT}/`);
  console.log(`- Login: http://localhost:${PORT}/login`);
  console.log(`- Register: http://localhost:${PORT}/register`);
  console.log(`- Products: http://localhost:${PORT}/products`);
  console.log(`- Product Detail: http://localhost:${PORT}/product-detail`);
  console.log(`- Cart: http://localhost:${PORT}/cart`);
  console.log(`- Checkout: http://localhost:${PORT}/checkout`);
  console.log(`- Vendor Dashboard: http://localhost:${PORT}/vendor-dashboard`);
});