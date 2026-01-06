const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const path = require('path');
const User = require('./models/User');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Middleware xác thực JWT
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id; // Sửa: decoded.id thay vì [decoded.id]
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// API: Đăng ký
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ thông tin!' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email đã được sử dụng!' });
    }

    const user = new User({ name, email, password });
    await user.save(); // Sửa: user.save()
    res.json({ message: 'Đăng ký thành công! Vui lòng đăng nhập.' });
  } catch (err) {
    console.error('Lỗi đăng ký:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// API: Đăng nhập
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ error: 'Email hoặc mật khẩu sai!' });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { name: user.name, id: user._id } }); // Sửa: user.name
  } catch (err) {
    console.error('Lỗi đăng nhập:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// API: Lấy giỏ hàng
app.get('/cart', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('cart');
    res.json(user.cart || []);
  } catch (err) {
    console.error('Lỗi lấy giỏ hàng:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Thêm / cập nhật / xóa item trong giỏ (quantity âm = xóa)
app.post('/cart/add', authMiddleware, async (req, res) => {
  try {
    const { productId, quantity = 1 } = req.body;
    if (!productId) return res.status(400).json({ error: 'Thiếu productId' });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const itemIndex = user.cart.findIndex(item => item.productId === productId);

    if (itemIndex > -1) {
      // Đã tồn tại → cập nhật số lượng
      user.cart[itemIndex].quantity += quantity;
      if (user.cart[itemIndex].quantity <= 0) {
        user.cart.splice(itemIndex, 1); // Xóa nếu <= 0
      }
    } else if (quantity > 0) {
      // Thêm mới
      user.cart.push({ productId, quantity });
    }

    await user.save(); // Sửa: user.save()
    res.json(user.cart);
  } catch (err) {
    console.error('Lỗi thêm giỏ hàng:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Xóa sạch giỏ hàng
app.post('/cart/clear', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.cart = [];
    await user.save(); // Sửa: user.save()
    res.json({ message: 'Giỏ hàng đã xóa sạch' });
  } catch (err) {
    console.error('Lỗi xóa giỏ:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Quên mật khẩu
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Email không tồn tại!' });

    const token = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 giờ

    await user.save();

    // Sửa: dùng backtick cho URL
    const resetUrl = `https://mini-shop.netlify.app/reset-password.html?token=${token}`; // Thay bằng URL frontend thật của bạn

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'MiniShop - Đặt lại mật khẩu',
      text: `Click link để đặt lại mật khẩu (hiệu lực 1 giờ):\n\n${resetUrl}`
    });

    res.json({ message: 'Link reset đã gửi đến email!' });
  } catch (err) {
    console.error('Lỗi gửi email reset:', err);
    res.status(500).json({ error: 'Lỗi gửi email' });
  }
});

// API: Reset mật khẩu
app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ error: 'Token không hợp lệ hoặc hết hạn!' });

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Đặt lại mật khẩu thành công!' });
  } catch (err) {
    console.error('Lỗi reset password:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// API Admin (tùy chọn)
app.get('/admin/users', authMiddleware, async (req, res) => {
  try {
    const admin = await User.findById(req.userId);
    if (!admin?.isAdmin) return res.status(403).json({ error: 'Không có quyền!' });

    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error('Lỗi admin/users:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve static files (frontend) - PHẢI ĐẶT SAU TẤT CẢ API
app.use(express.static(path.join(__dirname, '..')));

// Catch-all cho SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

// Kết nối MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Khởi động server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
