const mongoose = require('mongoose');
const winston = require('winston');

// Определяем схемы
const reportSchema = new mongoose.Schema({
  reporterId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reportedId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reason: { type: String, required: true },
  status: { type: String, enum: ['pending', 'reviewed', 'resolved'], default: 'pending' },
  createdAt: { type: Date, default: Date.now }
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
  referral_code: { type: String, unique: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isPaid: { type: Boolean, default: false },
  subscriptionExpiresAt: { type: Date },
  role: { type: String, enum: ['user', 'moderator'], default: 'user' },
  gender: { type: String, enum: ['male', 'female', 'other'], default: 'other' },
  age: { type: Number, min: 13, max: 120 }
});

const userStatsSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  points: { type: Number, default: 0 },
  life: { type: Number, default: 3 },
  total_online_time: { type: Number, default: 0 },
  last_online: { type: Date, default: Date.now },
  last_ad_view: { type: Date },
  ad_views: { type: Number, default: 0 },
});

// Определяем модели
const Report = mongoose.model('Report', reportSchema);
const User = mongoose.model('User', userSchema);
const UserStats = mongoose.model('UserStats', userStatsSchema);

// Логи
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Тест для Блока 62
async function runBlock62() {
  try {
    logger.info('Запуск проверки нарушений для уменьшения жизней');
    const reports = await Report.find({ status: 'pending' });
    for (const report of reports) {
      const userStats = await UserStats.findOne({ user_id: report.reportedId });
      if (!userStats) {
        logger.warn(`Статистика пользователя ${report.reportedId} не найдена`);
        continue;
      }
      userStats.life = Math.max(0, userStats.life - 1);
      report.status = 'resolved';
      await userStats.save();
      await report.save();
      logger.info(`Жизнь уменьшена для пользователя ${report.reportedId}, осталось: ${userStats.life}`);
      if (userStats.life === 0) {
        await User.updateOne({ _id: report.reportedId }, { isPaid: false });
        logger.info(`Пользователь ${report.reportedId} забанен (0 жизней)`);
      }
    }
  } catch (err) {
    logger.error('Ошибка при автоматической проверке нарушений:', err);
  }
}

// Подключение к базе
mongoose.connect('mongodb://127.0.0.1:27017/test', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    logger.info('Подключение к MongoDB успешно');
    runBlock62().then(() => {
      logger.info('Тест Блока 62 завершён');
      mongoose.connection.close();
    });
  })
  .catch(err => {
    logger.error('Ошибка подключения к MongoDB:', err);
  });