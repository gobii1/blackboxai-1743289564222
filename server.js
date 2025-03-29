const express = require('express');
const path = require('path');

const app = express();
const PORT = 8000;

// Serve static files
app.use(express.static(path.join(__dirname)));

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