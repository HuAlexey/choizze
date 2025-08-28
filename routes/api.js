const express = require('express');
const router = express.Router();
const User = require('../models/User');
const UserStats = require('../models/UserStats');
const Transaction = require('../models/Transaction');
const crypto = require('crypto');
const transporter = require('../config/nodemailer');

// Middleware для проверки токена
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Неверный токен' });
  }
};

// Создание платежа PAYEER
router.post('/payment/payeer', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const stats = await UserStats.findOne({ user_id: req.userId });
    
    if (stats.lives > 0 || stats.banChips > 0 || user.isPaid) {
      return res.status(400).json({ 
        error: 'Вы не можете повторно оплатить, так как не израсходовали фишки и/или жизни.' 
      });
    }
    
    const protectionCode = crypto.randomBytes(12).toString('hex');
    
    await new Transaction({
      userId: req.userId,
      amount: 1,
      method: 'payeer',
      transactionId: protectionCode
    }).save();
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Инструкция по оплате через PAYEER',
      text: `
        Для оплаты доступа в CHOIZZE:
        1. Перейдите в PAYEER
        2. Отправьте $1 на кошелек P1080587274
        3. В комментарии укажите код: ${protectionCode.substring(0, 12)}
        4. После оплаты доступ будет активирован автоматически
        
        Внимание: За все ошибки при оплате ответственность несете вы.
      `
    });
    
    res.json({ 
      message: 'Инструкция по оплате отправлена на ваш email',
      protectionCode: protectionCode.substring(0, 12)
    });
  } catch (err) {
    console.error('Ошибка создания платежа PAYEER:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

module.exports = router;