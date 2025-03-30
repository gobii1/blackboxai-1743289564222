const nodemailer = require('nodemailer');
const pool = require('./db');

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Notification types
const NOTIFICATION_TYPES = {
  LOW_STOCK: 'LOW_STOCK',
  NEW_ORDER: 'NEW_ORDER',
  ORDER_UPDATE: 'ORDER_UPDATE',
  PAYMENT_RECEIVED: 'PAYMENT_RECEIVED'
};

async function sendVendorNotification(vendorId, type, data) {
  try {
    // Get vendor email
    const [vendor] = await pool.query(
      'SELECT email, notification_preferences FROM users WHERE id = ?',
      [vendorId]
    );

    if (!vendor.length) return;

    // Check if vendor has this notification type enabled
    const prefs = JSON.parse(vendor[0].notification_preferences || '{}');
    if (prefs[type] === false) return;

    let subject, message;

    switch(type) {
      case NOTIFICATION_TYPES.LOW_STOCK:
        subject = `Low Stock Alert: ${data.productName}`;
        message = `Your product ${data.productName} is running low (${data.stock} remaining).`;
        break;
      case NOTIFICATION_TYPES.NEW_ORDER:
        subject = `New Order Received: #${data.orderId}`;
        message = `You have a new order #${data.orderId} for $${data.amount}.`;
        break;
      case NOTIFICATION_TYPES.ORDER_UPDATE:
        subject = `Order Update: #${data.orderId}`;
        message = `Order #${data.orderId} status changed to ${data.status}.`;
        break;
      case NOTIFICATION_TYPES.PAYMENT_RECEIVED:
        subject = `Payment Received: $${data.amount}`;
        message = `Payment of $${data.amount} for order #${data.orderId} has been processed.`;
        break;
      default:
        return;
    }

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: vendor[0].email,
      subject: subject,
      text: message,
      html: `<p>${message}</p>`
    });

    // Save notification to database
    await pool.query(
      'INSERT INTO vendor_notifications (vendor_id, type, message) VALUES (?, ?, ?)',
      [vendorId, type, message]
    );

  } catch (err) {
    console.error('Error sending vendor notification:', err);
  }
}

module.exports = {
  sendVendorNotification,
  NOTIFICATION_TYPES
};