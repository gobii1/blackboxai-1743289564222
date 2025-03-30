const express = require('express');
const router = express.Router();
const pool = require('./db');
const multer = require('multer');
const fs = require('fs');

// Image upload configuration
const upload = multer({ 
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Image upload endpoint
router.post('/upload', upload.single('image'), async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(403).json({ error: 'Unauthorized' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  try {
    const fileUrl = `/uploads/${req.file.filename}`;
    res.json({ 
      success: true,
      url: fileUrl,
      filename: req.file.originalname
    });
  } catch (err) {
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: err.message });
  }
});

// Order status update endpoint
router.put('/orders/:id/status', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const { status } = req.body;
    const validStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
    
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Verify vendor owns products in this order
    const [orderItems] = await pool.query(`
      SELECT oi.order_id 
      FROM order_items oi
      JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = ? AND p.vendor_id = ?
    `, [req.params.id, req.session.user.id]);

    if (orderItems.length === 0) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query(
      'UPDATE orders SET status = ? WHERE id = ?',
      [status, req.params.id]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Sales reports endpoint
router.get('/reports', async (req, res) => {
  if (req.session.user?.role !== 'vendor') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const { period = 'monthly' } = req.query;
    let dateFormat, groupBy;

    switch(period) {
      case 'daily':
        dateFormat = '%Y-%m-%d';
        groupBy = 'DATE(created_at)';
        break;
      case 'weekly':
        dateFormat = '%Y-%u';
        groupBy = 'YEARWEEK(created_at)';
        break;
      case 'monthly':
        dateFormat = '%Y-%m';
        groupBy = 'YEAR(created_at), MONTH(created_at)';
        break;
      default:
        return res.status(400).json({ error: 'Invalid period' });
    }

    const [report] = await pool.query(`
      SELECT 
        DATE_FORMAT(o.created_at, ?) as period,
        COUNT(DISTINCT o.id) as order_count,
        SUM(o.total) as total_revenue,
        COUNT(DISTINCT o.user_id) as customer_count
      FROM orders o
      JOIN order_items oi ON o.id = oi.order_id
      JOIN products p ON oi.product_id = p.id
      WHERE p.vendor_id = ?
      GROUP BY ${groupBy}
      ORDER BY o.created_at DESC
      LIMIT 12
    `, [dateFormat, req.session.user.id]);

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;