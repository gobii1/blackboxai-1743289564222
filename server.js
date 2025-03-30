const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const pool = require('./db');
const multer = require('multer');
const fs = require('fs');

// Image upload configuration
const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Ensure upload directory exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}
const bcrypt = require('bcrypt');
const saltRounds = 10;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// Security middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});

const app = express();
// Security middleware
app.use(helmet());
app.use(limiter);
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

// Mount vendor API
const vendorApi = require('./vendor-api');
app.use('/api/vendor', vendorApi);

// Vendor profile endpoints
app.put('/api/vendor/profile', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { name, email } = req.body;
    await pool.query(
      'UPDATE users SET name = ?, email = ? WHERE id = ?',
      [name, email, req.session.user.id]
    );
    
    // Update session
    req.session.user.name = name;
    req.session.user.email = email;
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/vendor/password', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { current, new: newPass } = req.body;
    
    // Verify current password
    const [user] = await pool.query(
      'SELECT password FROM users WHERE id = ?',
      [req.session.user.id]
    );
    
    const match = await bcrypt.compare(current, user[0].password);
    if (!match) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(newPass, saltRounds);
    await pool.query(
      'UPDATE users SET password = ? WHERE id = ?',
      [hashedPassword, req.session.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// API Routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT id, name, email, password, role FROM users WHERE email = ?',
      [email]
    );
    if (rows.length > 0) {
      const match = await bcrypt.compare(password, rows[0].password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      // Remove password before storing in session
      const { password: _, ...user } = rows[0];
      req.session.user = user;
      res.json(user);
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
// Vendor product endpoints
app.get('/api/vendor/products', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [products] = await pool.query(
      'SELECT * FROM products WHERE vendor_id = ?',
      [req.session.user.id]
    );
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vendor/products', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { name, description, price, stock, image_url } = req.body;
    const [result] = await pool.query(
      'INSERT INTO products (name, description, price, vendor_id, stock, image_url) VALUES (?, ?, ?, ?, ?, ?)',
      [name, description, price, req.session.user.id, stock, image_url]
    );
    
    // Log the action
    await pool.query(
      'INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, 'PRODUCT_ADD', `Added product ${name}`]
    );
    
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Bulk product operations
app.post('/api/vendor/products/bulk-delete', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { productIds } = req.body;
    
    // Verify all products belong to this vendor
    const [products] = await pool.query(
      'SELECT id FROM products WHERE id IN (?) AND vendor_id = ?',
      [productIds, req.session.user.id]
    );
    
    if (products.length !== productIds.length) {
      return res.status(403).json({ error: 'Unauthorized operation on some products' });
    }

    await pool.query(
      'DELETE FROM products WHERE id IN (?)',
      [productIds]
    );
    
    res.json({ success: true, count: productIds.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vendor/products/bulk-update', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { productIds, updateData } = req.body;
    
    // Verify all products belong to this vendor
    const [products] = await pool.query(
      'SELECT id FROM products WHERE id IN (?) AND vendor_id = ?',
      [productIds, req.session.user.id]
    );
    
    if (products.length !== productIds.length) {
      return res.status(403).json({ error: 'Unauthorized operation on some products' });
    }

    // Build dynamic update query
    const setClauses = [];
    const values = [];
    
    if (updateData.price !== undefined) {
      setClauses.push('price = ?');
      values.push(updateData.price);
    }
    if (updateData.stock !== undefined) {
      setClauses.push('stock = ?');
      values.push(updateData.stock);
    }
    if (updateData.status !== undefined) {
      setClauses.push('status = ?');
      values.push(updateData.status);
    }
    
    values.push(...productIds);
    
    await pool.query(
      `UPDATE products SET ${setClauses.join(', ')} WHERE id IN (?)`,
      values
    );
    
    res.json({ success: true, count: productIds.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/vendor/products/:id', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
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
    
    // Log the action
    await pool.query(
      'INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, 'PRODUCT_DELETE', `Deleted product ${req.params.id}`]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Vendor order endpoints
app.get('/api/vendor/orders', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [orders] = await pool.query(`
      SELECT o.id, u.email as customer_email, o.total, o.status, o.created_at
      FROM orders o
      JOIN users u ON o.user_id = u.id
      JOIN order_items oi ON o.id = oi.order_id
      JOIN products p ON oi.product_id = p.id
      WHERE p.vendor_id = ?
      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT 10
    `, [req.session.user.id]);
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Inventory management
app.get('/api/vendor/inventory', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [inventory] = await pool.query(`
      SELECT p.id, p.name, p.stock, p.price, 
             COUNT(oi.id) as sales_count,
             SUM(oi.quantity) as total_sold
      FROM products p
      LEFT JOIN order_items oi ON p.id = oi.product_id
      WHERE p.vendor_id = ?
      GROUP BY p.id
      ORDER BY p.stock ASC
    `, [req.session.user.id]);
    
    res.json(inventory);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vendor/inventory/restock', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { productId, quantity } = req.body;
    
    await pool.query(
      'UPDATE products SET stock = stock + ? WHERE id = ? AND vendor_id = ?',
      [quantity, productId, req.session.user.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/vendor/stats', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [products] = await pool.query(
      'SELECT COUNT(*) as count FROM products WHERE vendor_id = ?',
      [req.session.user.id]
    );
    
    const [orders] = await pool.query(`
      SELECT COUNT(DISTINCT o.id) as count, SUM(o.total) as revenue
      FROM orders o
      JOIN order_items oi ON o.id = oi.order_id
      JOIN products p ON oi.product_id = p.id
      WHERE p.vendor_id = ?
    `, [req.session.user.id]);
    
    res.json({
      products: products[0].count,
      orders: orders[0].count,
      revenue: orders[0].revenue || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Product categories endpoints
app.get('/api/vendor/categories', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [categories] = await pool.query(
      'SELECT * FROM product_categories WHERE vendor_id = ?',
      [req.session.user.id]
    );
    res.json(categories);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/vendor/categories', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { name, description } = req.body;
    const [result] = await pool.query(
      'INSERT INTO product_categories (name, description, vendor_id) VALUES (?, ?, ?)',
      [name, description, req.session.user.id]
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
// Admin endpoints
app.get('/api/admin/users', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [count] = await pool.query('SELECT COUNT(*) as count FROM users');
    res.json({ count: count[0].count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/products', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [count] = await pool.query('SELECT COUNT(*) as count FROM products');
    res.json({ count: count[0].count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/orders', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [count] = await pool.query('SELECT COUNT(*) as count FROM orders');
    res.json({ count: count[0].count });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin endpoints
app.get('/api/admin/all-users', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [users] = await pool.query('SELECT id, name, email, role FROM users');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Multi-admin endpoints
app.get('/api/admin/admins', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [admins] = await pool.query(
      'SELECT id, name, email FROM users WHERE role = "admin"'
    );
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/admin/promote', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { userId } = req.body;
    await pool.query(
      'UPDATE users SET role = "admin" WHERE id = ?',
      [userId]
    );
    
    await sendAdminNotification(
      'New Admin Added',
      `User ${userId} has been promoted to admin by ${req.session.user.email}`
    );
    
    // Log the action
    await pool.query(
      'INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, 'ADMIN_PROMOTE', `Promoted user ${userId} to admin`]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/update-user/:id', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const { role } = req.body;
    await pool.query('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
    
    // Log the action
    await pool.query(
      'INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, 'USER_UPDATE', `Updated user ${req.params.id} role to ${role}`]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/admin/delete-user/:id', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    
    // Log the action
    await pool.query(
      'INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
      [req.session.user.id, 'USER_DELETE', `Deleted user ${req.params.id}`]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Data export endpoints
app.get('/api/admin/export/users', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [users] = await pool.query('SELECT * FROM users');
    res.header('Content-Type', 'text/csv');
    res.attachment('users-export.csv');
    res.csv(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/export/orders', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [orders] = await pool.query(`
      SELECT o.id, u.email, o.total, o.created_at, 
             GROUP_CONCAT(p.name SEPARATOR ', ') as products
      FROM orders o
      JOIN users u ON o.user_id = u.id
      JOIN order_items oi ON o.id = oi.order_id
      JOIN products p ON oi.product_id = p.id
      GROUP BY o.id
    `);
    res.header('Content-Type', 'text/csv');
    res.attachment('orders-export.csv');
    res.csv(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/audit-logs', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [logs] = await pool.query(
      'SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 50'
    );
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/activity', async (req, res) => {
  if (req.session.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const [activity] = await pool.query(
      'SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT 5'
    );
    res.json(activity);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/check-auth', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(req.session.user);
});

// Password reset endpoints
const crypto = require('crypto');

app.post('/api/request-password-reset', async (req, res) => {
  const { email } = req.body;
  try {
    const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate reset token
    const token = crypto.randomBytes(20).toString('hex');
    const expires = Date.now() + 3600000; // 1 hour
    
    await pool.query(
      'UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?',
      [token, expires, email]
    );
    
    // In production: Send email with reset link
    console.log(`Password reset token for ${email}: ${token}`);
    res.json({ message: 'Password reset link sent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  try {
    const [user] = await pool.query(
      'SELECT * FROM users WHERE reset_token = ? AND reset_expires > ?',
      [token, Date.now()]
    );
    
    if (user.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await pool.query(
      'UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?',
      [hashedPassword, user[0].id]
    );
    
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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