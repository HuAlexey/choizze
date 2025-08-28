// Блок 45: Middleware для ограничения банов
const User = require('../models/User');
const UserStats = require('../models/UserStats');
const Report = require('../models/Report');
const moment = require('moment');

const banLimit = async (req, res, next) => {
  try {
    const userId = req.userId;
    const startOfDay = moment().startOf('day').toDate();
    const endOfDay = moment().endOf('day').toDate();

    const banCount = await Report.countDocuments({
      reporterId: userId,
      createdAt: { $gte: startOfDay, $lte: endOfDay }
    });

    if (banCount >= 3) {
      return res.status(403).json({ error: 'Лимит банов на сегодня достигнут (максимум 3 бана в сутки)' });
    }

    const user = await User.findById(userId);
    const stats = await UserStats.findOne({ user_id: userId });

    if (!user.isPaid && !stats.banChips) {
      return res.status(403).json({ error: 'Недостаточно фишек для бана или отсутствует полный доступ' });
    }

    next();
  } catch (err) {
    console.error('Ошибка в banLimit middleware:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
};

module.exports = banLimit;