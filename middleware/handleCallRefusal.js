const RefusalHistory = require('../models/RefusalHistory');
const UserStats = require('../models/UserStats');

const handleCallRefusal = async (req, res, next) => {
  try {
    const { userId, refusedUserId } = req.body;

    await RefusalHistory.create({
      userId,
      refusedUserId,
      timestamp: Date.now()
    });

    await UserStats.findOneAndUpdate(
      { user_id: userId },
      { $inc: { refused_calls: 1 } }
    );

    next();
  } catch (err) {
    console.error('Ошибка в handleCallRefusal middleware:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
};

module.exports = handleCallRefusal;