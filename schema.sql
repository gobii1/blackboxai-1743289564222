CREATE DATABASE IF NOT EXISTS marketplace;
USE marketplace;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(100) NOT NULL,
  role ENUM('customer', 'vendor', 'admin') DEFAULT 'customer',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  vendor_id INT NOT NULL,
  image_url VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (vendor_id) REFERENCES users(id)
);

CREATE TABLE orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  total DECIMAL(10,2) NOT NULL,
  status ENUM('pending', 'processing', 'shipped', 'delivered') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE order_items (
  id INT AUTO_INCREMENT PRIMARY KEY,
  order_id INT NOT NULL,
  product_id INT NOT NULL,
  quantity INT NOT NULL,
  price DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (order_id) REFERENCES orders(id),
  FOREIGN KEY (product_id) REFERENCES products(id)
);

-- Sample data
INSERT INTO users (name, email, password, role) VALUES 
('Admin', 'admin@marketplace.com', 'admin123', 'admin'),
('Vendor A', 'vendor@marketplace.com', 'vendor123', 'vendor'),
('Customer', 'customer@marketplace.com', 'customer123', 'customer');

INSERT INTO products (name, description, price, vendor_id, image_url) VALUES
('Premium Skin', 'High-quality skin with advanced features', 29.99, 2, 'https://images.pexels.com/photos/90946/pexels-photo-90946.jpeg'),
('Deluxe Package', 'Complete package with all features', 49.99, 2, 'https://images.pexels.com/photos/1036936/pexels-photo-1036936.jpeg');