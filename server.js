// Блок 1: Импорт зависимостей
const express = require('express');

// Блок 2: Импорт HTTP
const http = require('http');

// Блок 3: Импорт Socket.IO
const socketIo = require('socket.io');

// Блок 4: Импорт Mongoose
const mongoose = require('mongoose');

// Блок 5: Импорт JWT
const jwt = require('jsonwebtoken');

// Блок 6: Импорт Bcrypt
const bcrypt = require('bcrypt');

// Блок 7: Импорт Dotenv
const dotenv = require('dotenv');

// Блок 8: Импорт Crypto
const crypto = require('crypto');

// Блок 9: Импорт Nodemailer
const nodemailer = require('nodemailer');

// Блок 10: Импорт Express Validator
const { check, validationResult } = require('express-validator');

// Блок 11: Импорт Winston
const winston = require('winston');

// Блок 12: Импорт Moment
const moment = require('moment');

// Блок 13: Импорт Node-Cron
const cron = require('node-cron');

// Блок 14: Импорт TronWeb
const { TronWeb } = require('tronweb');

// Блок 14.1: Бесплатный перевод через MyMemory
const axios = require('axios');

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

const translateMessage = async (text, targetLang) => {
  try {
    const response = await axios.get('https://api.mymemory.translated.net/get', {
      params: {
        q: text,
        langpair: `auto|${targetLang}`
      }
    });
    return response.data.responseData.translatedText || text;
  } catch (err) {
    logger.error('Ошибка перевода MyMemory:', err);
    return text; // возвращаем оригинал при ошибке
  }
};

// Блок 15: Импорт моделей
const User = require('./models/User');
const UserStats = require('./models/UserStats');
const Payment = require('./models/Payment');
const FriendRequest = require('./models/FriendRequest');
const Report = require('./models/Report');
const Message = require('./models/Message');
const Appeal = require('./models/Appeal');
const Post = require('./models/Post');
const Comment = require('./models/Comment');
const UserActivity = require('./models/UserActivity');
const RefusalHistory = require('./models/RefusalHistory');
const ChatSession = require('./models/ChatSession');
const AdImpression = require('./models/AdImpression');
const Quiz = require('./models/Quiz');
const Withdrawal = require('./models/Withdrawal');

// Блок 33: Загрузка окружения
dotenv.config();

// Блок 34: Инициализация Express
const app = express();

// Добавляем middleware и маршрут
app.use(express.json());
const refusalRouter = require('./routes/refusal');
app.use('/api', refusalRouter);

// Блок 35: Создание HTTP-сервера
const server = http.createServer(app);

// Блок 36: Инициализация Socket.IO
const io = new socketIo.Server(server);

io.on('connection', (socket) => {
  socket.on('findPartner', async ({ userId }, callback) => {
    try {
      const refusals = await RefusalHistory.find({ userId }).select('refusedUserId');
      const refusedIds = refusals.map(refusal => refusal.refusedUserId.toString());

      const availableUsers = await User.find({
        _id: { $ne: userId, $nin: refusedIds },
        status: 'online'
      });

      if (availableUsers.length === 0) {
        callback({ error: 'Нет доступных собеседников' });
        return;
      }

      const selectedPartner = availableUsers[0];
      callback({ partnerId: selectedPartner._id });
    } catch (err) {
      console.error('Ошибка подбора собеседника:', err);
      callback({ error: 'Ошибка сервера' });
    }
  });

  socket.on('endSearch', async ({ userId }) => {
    try {
      await RefusalHistory.deleteMany({ userId });
      console.log(`Очищены записи отказов для пользователя ${userId}`);
    } catch (err) {
      console.error('Ошибка очистки RefusalHistory:', err);
    }
  });
});

// Блок 37: Установка порта
const PORT = process.env.PORT || 3000;

// Блок 38: Настройка логирования
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Блок 39: Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => logger.info('Подключено к MongoDB'))
  .catch(err => logger.error('Ошибка подключения к MongoDB:', err));

// Блок 40: Настройка Nodemailer
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Блок 41: Middleware для обработки JSON
app.use(express.json());
app.use('/api', refusalRouter);

// Блок 42: Проверка JWT
const verifyToken = async (req, res, next) => {
  let token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'Токен не предоставлен' });
  if (token.startsWith('Bearer ')) token = token.slice(7);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    const user = await User.findById(req.userId);
    if (!user || !user.emailVerified || !user.rulesAgreed) {
      return res.status(401).json({ error: 'Пользователь не подтвержден или не принял правила' });
    }
    
    if (user.status === 'busy') {
      return res.status(403).json({ error: 'Пользователь занят' });
    }
    
    const stats = await UserStats.findOne({ user_id: req.userId });
    if (!stats) return res.status(404).json({ error: 'Статистика не найдена' });
    
    // Проверка подписки
    if (!user.isPaid && user.subscriptionExpiresAt < new Date()) {
      // Отправляем уведомление только один раз
      if (!user.notifiedExpired) {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Ваша подписка в CHOIZZE истекла',
          text: 'Ваша подписка истекла. Для продолжения использования сервиса оплатите доступ или посмотрите рекламу.'
        });
        user.notifiedExpired = true;
        await user.save();
      }
      return res.status(403).json({ error: 'Доступ истек. Оплатите или посмотрите рекламу' });
    }
    
    stats.last_online = new Date();
    stats.total_online_time += 60;
    await stats.save();
    req.user = user;
    next();
  } catch (err) {
    logger.error('Ошибка проверки токена:', err);
    res.status(401).json({ error: 'Недействительный токен' });
  }
};

// Блок 43: Валидация регистрации
const validateRegistration = [
  check('username').isLength({ min: 3 }).withMessage('Имя пользователя минимум 3 символа'),
  check('email').isEmail().custom(value => {
    const domains = ['yahoo.com', 'gmail.com', 'mail.ru', 'yandex.ru', 'rambler.ru'];
    if (!domains.includes(value.split('@')[1])) throw new Error('Недопустимый домен почты');
    return true;
  }),
  check('password').isLength({ min: 6 }).withMessage('Пароль минимум 6 символов'),
  check('birthdate').custom(value => {
    const age = moment().diff(moment(value), 'years');
    if (age < 14 || age > 99) throw new Error('Возраст должен быть 14-99 лет');
    return true;
  }),
  check('gender').isIn(['male', 'female']).withMessage('Укажите пол: male или female'),
  check('preferredGender').isIn(['male', 'female', 'any']).withMessage('Недопустимый выбор пола собеседника'),
  check('preferredAgeMin').isInt({ min: 14, max: 99 }).withMessage('Минимальный возраст 14-99'),
  check('preferredAgeMax').isInt({ min: 14, max: 99 }).custom((val, { req }) => {
    if (val < req.body.preferredAgeMin) throw new Error('Максимальный возраст не может быть меньше минимального');
    return true;
  })
];

// Блок 44: Валидация жалобы
const validateReport = [
  check('reportedId').isMongoId().withMessage('Неверный ID пользователя'),
  check('reason').notEmpty().withMessage('Укажите причину')
];

// Блок 45: Валидация апелляции
const validateAppeal = [
  check('reportId').isMongoId().withMessage('Неверный ID жалобы'),
  check('message').notEmpty().withMessage('Укажите сообщение')
];

// Блок 46: Валидация поста
const validatePost = [
  check('content').notEmpty().withMessage('Укажите содержимое поста')
];

// Блок 47: Валидация лайка
const validateLike = [
  check('postId').isMongoId().withMessage('Неверный ID поста')
];

// Блок 48: Валидация репоста
const validateRepost = [
  check('postId').isMongoId().withMessage('Неверный ID поста')
];

// Блок 49: Валидация комментария
const validateComment = [
  check('postId').isMongoId().withMessage('Неверный ID поста'),
  check('content').notEmpty().withMessage('Укажите содержимое комментария')
];

// Блок 50: Валидация викторины
const validateQuiz = [
  check('type').isIn(['interaction', 'words', 'reaction', 'logic']).withMessage('Неверный тип викторины'),
  check('won').isBoolean().withMessage('Укажите результат викторины')
];

// Блок 51: Инициализация TronWeb
const tronWeb = new TronWeb({
  fullHost: 'https://api.trongrid.io',
  headers: { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY }
});

// Блок 52: Генерация реферального кода
const generateReferralCode = () => crypto.randomBytes(4).toString('hex');

// Блок 53: Генерация токена подтверждения
const generateVerificationToken = () => crypto.randomBytes(32).toString('hex');

// Блок 54: Отправка email подтверждения
const sendVerificationEmail = async (email, token) => {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Подтверждение регистрации CHOIZZE',
    html: `Пройдите по ссылке для подтверждения: <a href="http://localhost:${process.env.PORT}/api/auth/verify/${token}">Подтвердить</a><br><br>
Правила:<br>
<b>Правила общения</b><br>
Эти правила созданы, чтобы всем было приятно общаться. Прочитайте их — так у вас не возникнет проблем, и диалоги будут в радость!<br>
<b>Как это работает?</b><br>
- Если собеседник ведёт себя плохо, отправьте жалобу.<br>
- Пока жалобы нет, диалог остаётся приватным — мы его не видим.<br>
- После жалобы модератор проверит ситуацию. Если нарушение подтвердится, пользователя заблокируют.<br>
<b>Главные запреты:</b><br>
- Спам и реклама — не кидайте ссылки просто так, но делитесь полезным в дружеской беседе.<br>
- Хамство и агрессия — оскорбления, угрозы и унижения запрещены.<br>
- Пустая болтовня — не забивайте диалог ерундой.<br>
- Нежелательный флирт — остановитесь, если собеседнику некомфортно.<br>
- Провокации — не подталкивайте других нарушать правила.<br>
- Запрещённые темы — никаких политики, экстремизма и призывов нарушать законы.`
  });
};

// Блок 55: Регистрация пользователя
app.post('/api/register', validateRegistration, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { username, email, password, birthdate, gender, preferredGender, preferredAgeMin, preferredAgeMax, referral } = req.body;
    if (await User.findOne({ $or: [{ email }, { username }] })) {
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }
    const style = gender === 'male' ? 'cosmic' : 'pink_unicorn';
    const verificationToken = generateVerificationToken();
    
    // Обработка реферала
    let referredBy = null;
    if (referral) {
      const referrer = await User.findOne({ referral_code: referral });
      if (referrer) {
        // Проверяем лимит рефералов (3 в день)
        const referrerStats = await UserStats.findOne({ user_id: referrer._id });
        if (referrerStats && referrerStats.referralsToday < 3) {
          referredBy = referrer._id;
          referrerStats.referralsToday += 1;
          referrerStats.cp += parseFloat(process.env.CP_REF_REGISTER);
          await referrerStats.save();
        } else {
          // Превышен лимит - привязываем к Spectator
          const spectator = await User.findOne({ username: 'Spectator' });
          if (spectator) {
            referredBy = spectator._id;
            const spectatorStats = await UserStats.findOne({ user_id: spectator._id });
            spectatorStats.cp += parseFloat(process.env.CP_REF_REGISTER);
            await spectatorStats.save();
          }
        }
      }
    }
    
    const user = new User({
      username,
      email,
      password: await bcrypt.hash(password, 10),
      birthdate,
      gender,
      preferredGender,
      preferredAgeMin,
      preferredAgeMax,
      style,
      referral_code: generateReferralCode(),
      referred_by: referredBy,
      subscriptionExpiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 часа календарных
      verificationToken
    });
    await user.save();
    const stats = new UserStats({ 
      user_id: user._id, 
      lives: 0,
      chips: 0,
      cp: 0,
      banChips: 0,
      ad_views: 0,
      chat_hours_today: 0,
      monthly_appeals: 0,
      last_online: new Date(),
      daily_reset: new Date(),
      monthly_reset: new Date(),
      missed_calls: 0,
      refused_calls: 0,
      lastActivityCheck: new Date(),
      referralsToday: 0
    });
    await stats.save();
    await sendVerificationEmail(email, verificationToken);
    res.json({ message: 'Спасибо, подтверждение выслано на email' });
  } catch (err) {
    logger.error('Ошибка регистрации:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 56: Подтверждение email
app.get('/api/auth/verify/:token', async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).json({ error: 'Недействительный токен' });
    user.emailVerified = true;
    user.verificationToken = null;
    await user.save();
    res.json({ message: 'Регистрация завершена. Обращайтесь в удобство.' });
  } catch (err) {
    logger.error('Ошибка подтверждения email:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 57: Подача жалобы (объединенный обработчик)
app.post('/api/report', verifyToken, validateReport, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { reportedId, reason } = req.body;
    const today = moment().startOf('day');

    // 1. Проверка наличия фишек у жалобщика (только для пользователей с полным доступом)
    const reporterStats = await UserStats.findOne({ user_id: req.userId });
    const reporterUser = await User.findById(req.userId);
    
    // Только пользователи с полным доступом могут подавать жалобы
    if (!reporterUser.isPaid && reporterUser.subscriptionExpiresAt < new Date()) {
      return res.status(400).json({ error: 'Только пользователи с полным доступом могут подавать жалобы' });
    }
    
    if (reporterStats.banChips <= 0) {
      return res.status(400).json({ error: 'Недостаточно фишек для подачи жалобы' });
    }

    // 2. Проверка лимита жалоб (3 в день на одного пользователя)
    const bansToday = await Report.countDocuments({
      reportedId,
      createdAt: { $gte: today }
    });

    if (bansToday >= 3) {
      return res.status(400).json({ error: 'Достигнут лимит жалоб на этого пользователя (3 в день)' });
    }

    // 3. Списание фишки
    reporterStats.banChips -= 1;
    await reporterStats.save();

    // 4. Создание жалобы
    const report = new Report({
      reporterId: req.userId,
      reportedId,
      reason
    });
    await report.save();

    // 5. Обработка нарушителя
    const reportedStats = await UserStats.findOne({ user_id: reportedId });
    const reportedUser = await User.findById(reportedId);
    
    if (reportedStats.lives > 0) {
      reportedStats.lives -= 1;
      await reportedStats.save();

      // Если жизни закончились
      if (reportedStats.lives === 0) {
        reportedUser.status = 'busy';
        await reportedUser.save();

        // Удаление pending апелляций
        await Appeal.deleteMany({
          userId: reportedId,
          status: 'pending'
        });

        // Уведомление нарушителя о бане
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: reportedUser.email,
          subject: 'Ваш аккаунт заблокирован в CHOIZZE',
          text: 'Вы потеряли все жизни из-за жалоб. Ваш статус изменен на "Занят". Для продолжения общения:\n1. Оплатите полный доступ\n2. Подайте апелляцию в разделе "История"'
        });
      }
    }

    // 6. Уведомление о полученной жалобе
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: reportedUser.email,
      subject: 'Новая жалоба в CHOIZZE',
      text: `Пользователь ${req.user.username} подал на вас жалобу по причине: "${reason}".\n\nВы можете подать апелляцию в течение 24 часов в разделе "История".`
    });

    res.json({
      message: 'Жалоба успешно подана',
      chipsRemaining: reporterStats.banChips,
      livesRemaining: reportedStats.lives
    });

  } catch (err) {
    logger.error('Ошибка подачи жалобы:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 58: Подача апелляции
app.post('/api/appeal', verifyToken, validateAppeal, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { reportId, message } = req.body;
    const report = await Report.findById(reportId);
    if (!report || report.reportedId.toString() !== req.userId || report.status !== 'pending') {
      return res.status(403).json({ error: 'Недействительная жалоба' });
    }
    const stats = await UserStats.findOne({ user_id: req.userId });
    const user = await User.findById(req.userId);
    
    // Только пользователи с полным доступом могут подавать апелляции
    if (!user.isPaid && user.subscriptionExpiresAt < new Date()) {
      return res.status(403).json({ error: 'Только пользователи с полным доступом могут подавать апелляции' });
    }
    
    if (stats.lives <= 0) return res.status(403).json({ error: 'Нет жизней для подачи апелляции' });
    if (stats.monthly_appeals >= 5) return res.status(400).json({ error: 'Лимит 5 апелляций в месяц' });
    const appeal = new Appeal({ userId: req.userId, reportId, message });
    stats.monthly_appeals += 1;
    await stats.save();
    await appeal.save();
    res.json({ message: 'Апелляция подана' });
  } catch (err) {
    logger.error('Ошибка апелляции:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 59: Модерация жалобы
app.post('/api/moderate', verifyToken, async (req, res) => {
  try {
    const { reportId, decision } = req.body;
    const report = await Report.findById(reportId);
    if (!report || report.status !== 'pending') return res.status(403).json({ error: 'Недействительная жалоба' });
    report.status = 'resolved';
    await report.save();
    if (decision === 'approve') {
      const reportedStats = await UserStats.findOne({ user_id: report.reportedId });
      if (reportedStats.lives > 0) {
        reportedStats.lives -= 1;
        if (reportedStats.lives === 0) {
          const user = await User.findById(report.reportedId);
          user.status = 'busy';
          await user.save();
          await Appeal.deleteMany({ userId: report.reportedId, status: 'pending' });
        }
        await reportedStats.save();
      }
    } else if (decision === 'reject') {
      const appeal = await Appeal.findOne({ reportId });
      if (appeal && appeal.status === 'pending') {
        appeal.status = 'approved';
        await appeal.save();
        
        // Компенсация за необоснованный бан (только для пользователей с полным доступом)
        const appealUser = await User.findById(appeal.userId);
        if (appealUser.isPaid) {
          const appealStats = await UserStats.findOne({ user_id: appeal.userId });
          appealStats.cp += parseFloat(process.env.CP_APPEAL_COMPENSATION || 50);
          await appealStats.save();
        }
      }
    }
    res.json({ message: 'Жалоба обработана' });
  } catch (err) {
    logger.error('Ошибка модерации:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 60: Получение истории чатов
const getChatHistory = async (userId) => {
  const messages = await Message.find({
    $or: [{ sender_id: userId }, { receiver_id: userId }],
    created_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
  }).populate('sender_id receiver_id', 'username');
  return messages.map(msg => ({
    type: 'chat',
    with: msg.sender_id._id.equals(userId) ? msg.receiver_id.username : msg.sender_id.username,
    status: 'success',
    timestamp: msg.created_at
  }));
};

// Блок 61: Получение истории пропущенных звонков
const getMissedCallsHistory = async (userId) => {
  const missedCalls = await Message.find({
    receiver_id: userId,
    message_text: 'call_missed',
    created_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
  }).populate('sender_id', 'username');
  return missedCalls.map(call => ({
    type: 'missed_call',
    from: call.sender_id.username,
    timestamp: call.created_at
  }));
};

// Блок 62: Получение истории поданных жалоб
const getBansGivenHistory = async (userId) => {
  const bansGiven = await Report.find({ reporterId: userId }).populate('reportedId', 'username');
  return bansGiven.map(ban => ({
    type: 'ban_given',
    with: ban.reportedId.username,
    reason: ban.reason,
    timestamp: ban.createdAt
  }));
};

// Блок 63: Получение истории полученных жалоб
const getBansReceivedHistory = async (userId) => {
  const bansReceived = await Report.find({ reportedId: userId }).populate('reporterId', 'username');
  return bansReceived.map(ban => ({
    type: 'ban_received',
    from: ban.reporterId.username,
    reason: ban.reason,
    timestamp: ban.createdAt
  }));
};

// Блок 64: Получение истории запросов в друзья
const getFriendRequestsHistory = async (userId) => {
  const friendRequests = await FriendRequest.find({
    $or: [{ from: userId }, { to: userId }],
    createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
  }).populate('from to', 'username');
  return friendRequests.map(req => ({
    type: req.from._id.equals(userId) ? 'friend_request_sent' : 'friend_request_received',
    with: req.from._id.equals(userId) ? req.to.username : req.from.username,
    status: req.status,
    timestamp: req.createdAt
  }));
};

// Блок 65: Объединение истории
app.get('/api/history', verifyToken, async (req, res) => {
  try {
    const userId = req.userId;
    const history = [
      ...(await getChatHistory(userId)),
      ...(await getMissedCallsHistory(userId)),
      ...(await getBansGivenHistory(userId)),
      ...(await getBansReceivedHistory(userId)),
      ...(await getFriendRequestsHistory(userId))
    ];
    res.json(history.sort((a, b) => b.timestamp - a.timestamp));
  } catch (err) {
    logger.error('Ошибка получения истории:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 66: Поиск собеседников с учётом истории отказов
app.get('/api/match', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const stats = await UserStats.findOne({ user_id: req.userId });

    if (stats.lives <= 0 && !user.isPaid && user.subscriptionExpiresAt < new Date()) {
      return res.status(403).json({ error: 'Нет доступных жизней или подписки' });
    }

    // Исключаем друзей
    const friends = await FriendRequest.find({
      $or: [{ from: req.userId }, { to: req.userId }],
      status: 'accepted'
    });
    const friendIds = friends.map(f => f.from._id.equals(req.userId) ? f.to : f.from);

    // Исключаем недавние чаты (72 часа)
    const recentChats = await Message.find({
      $or: [{ sender_id: req.userId }, { receiver_id: req.userId }],
      created_at: { $gte: new Date(Date.now() - 72 * 60 * 60 * 1000) }
    });
    const recentChatIds = recentChats.map(m =>
      m.sender_id._id.equals(req.userId) ? m.receiver_id : m.sender_id
    );

    // Исключаем историю отказов (72 часа)
    const refusalHistory = await RefusalHistory.find({
      userId: req.userId,
      createdAt: { $gte: new Date(Date.now() - 72 * 60 * 60 * 1000) }
    });
    const refusedIds72h = refusalHistory.map(r => r.refusedId);

    // Получаем всех пользователей, от которых был отказ (вне зависимости от времени)
    const allRefusalHistory = await RefusalHistory.find({
      userId: req.userId
    });
    const allRefusedIds = allRefusalHistory.map(r => r.refusedId);

    // Формируем запрос
    const excludeIds = [...friendIds, ...recentChatIds, ...refusedIds72h];
    const query = {
      _id: { $ne: req.userId, $nin: excludeIds },
      status: 'online',
      emailVerified: true,
      rulesAgreed: true,
      subscriptionExpiresAt: { $gte: new Date() }
    };

    if (user.preferredGender !== 'any') query.gender = user.preferredGender;

    const matches = await User.find(query).select('username gender birthdate');
    const filteredMatches = matches.filter(m => {
      const age = moment().diff(moment(m.birthdate), 'years');
      return age >= user.preferredAgeMin && age <= user.preferredAgeMax;
    });

    // Разделяем на тех, от которых не было отказа и тех, от которых был отказ
    const nonRefusedMatches = [];
    const refusedMatches = [];
    for (const match of filteredMatches) {
      if (allRefusedIds.includes(match._id)) {
        refusedMatches.push(match);
      } else {
        nonRefusedMatches.push(match);
      }
    }

    // Перемешиваем каждую группу
    shuffleArray(nonRefusedMatches);
    shuffleArray(refusedMatches);

    // Объединяем: сначала не отказанные, потом отказанные
    const orderedMatches = [...nonRefusedMatches, ...refusedMatches];

    // Если нет подходящих собеседников, предлагаем ИИ-бота
    if (orderedMatches.length === 0) {
      return res.json([{
        id: 'ai_bot',
        username: 'AI Bot',
        gender: 'ai',
        age: 0,
        isBot: true
      }]);
    }

    res.json(orderedMatches.map(m => ({
      id: m._id,
      username: m.username,
      gender: m.gender,
      age: moment().diff(moment(m.birthdate), 'years')
    })));

  } catch (err) {
    logger.error('Ошибка поиска собеседников:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Вспомогательная функция для перемешивания массива
function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

// Блок 67: Создание поста
app.post('/api/post', verifyToken, validatePost, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { content } = req.body;
    const post = new Post({ userId: req.userId, content });
    await post.save();
    res.json({ message: 'Пост создан', post });
  } catch (err) {
    logger.error('Ошибка создания поста:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 68: Добавление лайка
app.post('/api/like', verifyToken, validateLike, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { postId } = req.body;
    const post = await Post.findById(postId);
    if (!post) return res.status(404).json({ error: 'Пост не найден' });
    if (post.likes.includes(req.userId)) return res.status(400).json({ error: 'Уже лайкнуто' });
    post.likes.push(req.userId);
    await post.save();
    const stats = await UserStats.findOne({ user_id: req.userId });
    stats.cp += parseFloat(process.env.CP_LIKE);
    await stats.save();
    res.json({ message: 'Лайк добавлен' });
  } catch (err) {
    logger.error('Ошибка лайка:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 69: Добавление репоста
app.post('/api/repost', verifyToken, validateRepost, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { postId } = req.body;
    const post = await Post.findById(postId);
    if (!post) return res.status(404).json({ error: 'Пост не найден' });
    if (post.reposts.includes(req.userId)) return res.status(400).json({ error: 'Уже репостнуто' });
    post.reposts.push(req.userId);
    await post.save();
    const stats = await UserStats.findOne({ user_id: req.userId });
    stats.cp += parseFloat(process.env.CP_REPOST);
    await stats.save();
    res.json({ message: 'Репост добавлен' });
  } catch (err) {
    logger.error('Ошибка репоста:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 70: Добавление комментария
app.post('/api/comment', verifyToken, validateComment, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { postId, content } = req.body;
    const comment = new Comment({ postId, userId: req.userId, content });
    await comment.save();
    const stats = await UserStats.findOne({ user_id: req.userId });
    stats.cp += parseFloat(process.env.CP_COMMENT);
    await stats.save();
    res.json({ message: 'Комментарий добавлен', comment });
  } catch (err) {
    logger.error('Ошибка комментария:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 71: Обработка викторины
app.post('/api/quiz', verifyToken, validateQuiz, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { type, won } = req.body;
    const user = await User.findById(req.userId);
    
    // Проверка, что у пользователя есть время для участия в викторинах
    if (user.subscriptionExpiresAt < new Date() && !user.isPaid) {
      return res.status(403).json({ error: 'Время для участия в викторинах истекло' });
    }
    
    if (!won) return res.json({ message: 'Викторина не пройдена' });
    const stats = await UserStats.findOne({ user_id: req.userId });
    let cpEarned = 0;
    switch (type) {
      case 'interaction': cpEarned = parseFloat(process.env.CP_QUIZ_INTERACTION); break;
      case 'words': cpEarned = parseFloat(process.env.CP_QUIZ_WORDS); break;
      case 'reaction': cpEarned = parseFloat(process.env.CP_QUIZ_REACTION); break;
      case 'logic': cpEarned = parseFloat(process.env.CP_QUIZ_LOGIC); break;
    }
    stats.cp += cpEarned;
    await stats.save();
    
    // Сохраняем результат викторины
    const quizResult = new Quiz({
      userId: req.userId,
      quizType: type,
      cpEarned,
      completedAt: new Date()
    });
    await quizResult.save();
    
    res.json({ message: 'CP начислены', cpEarned });
  } catch (err) {
    logger.error('Ошибка викторины:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 72: Обработка просмотра рекламы
app.post('/api/ad-view', verifyToken, async (req, res) => {
  try {
    const stats = await UserStats.findOne({ user_id: req.userId });
    const user = await User.findById(req.userId);
    
    // Проверка, не просмотрел ли пользователь уже 200 реклам
    if (stats.ad_views >= 200 && !user.fullAccessActivated) {
      return res.status(400).json({ 
        error: 'Вы уже просмотрели 200 реклам и получили полный доступ. Дальнейшие просмотры не учитываются.' 
      });
    }
    
    stats.ad_views += 1;
    
    // Начисляем 15 минут за каждый просмотр
    if (!user.isPaid || user.subscriptionExpiresAt < new Date()) {
      const additionalTime = 15 * 60 * 1000; // 15 минут в миллисекундах
      user.subscriptionExpiresAt = new Date(Math.max(
        user.subscriptionExpiresAt.getTime() || Date.now(),
        Date.now() + additionalTime
      ));
      await user.save();
    }
    
    // Проверяем, достиг ли пользователь 200 просмотров
    if (stats.ad_views >= 200 && !user.fullAccessActivated) {
      user.isPaid = true;
      user.subscriptionExpiresAt = moment().add(30, 'days').toDate();
      user.fullAccessActivated = true; // Флаг, что активация уже была
      stats.lives = 3;
      stats.banChips = 15;
      await user.save();
      await stats.save();
      
      // Отправляем уведомление о получении полного доступа
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Полный доступ в CHOIZZE',
        text: 'Поздравляем! Вы получили полный доступ на 30 дней за просмотр 200 реклам. Активируйте его в личном кабинете.'
      });
      
      return res.json({ 
        message: 'Поздравляем! Вы получили полный доступ на 30 дней!', 
        ad_views: stats.ad_views,
        fullAccess: true
      });
    }
    
    await stats.save();
    res.json({ 
      message: 'Просмотр рекламы учтен', 
      ad_views: stats.ad_views,
      timeAdded: '15 минут'
    });
  } catch (err) {
    logger.error('Ошибка обработки просмотра рекламы:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 73: Socket.IO подключение (полностью обновлен)
io.on('connection', socket => {
  const token = socket.handshake.auth.token;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    socket.join(`user:${socket.userId}`);
    logger.info(`Пользователь ${socket.userId} подключился`);
  } catch (err) {
    logger.error('Ошибка аутентификации Socket.IO:', err);
    socket.disconnect();
    return;
  }

  // Блок 73.1: начало чата
  socket.on('start_chat', async ({ roomId, partnerId }) => {
    socket.join(roomId);
    socket.chatRoom = roomId;
    socket.partnerId = partnerId;
    socket.chatStart = Date.now();
    socket.disconnectTimer = null;
    
    // Отправляем событие для анимации соединения
    io.to(roomId).emit('connection_animation', { 
      userId: socket.userId, 
      partnerId 
    });
  });

  // Блок 73.2: пользователь нажал «Выйти»
  socket.on('leave_chat', async () => {
    if (!socket.chatRoom) return;

    const elapsed = Date.now() - socket.chatStart;
    if (elapsed < 5 * 60 * 1000) {
      // Показываем подтверждение выхода
      socket.emit('confirm_exit', {
        message: 'Вы действительно хотите выйти? 5 минут обязательного общения не закончено, и вы автоматически получите бан',
        roomId: socket.chatRoom
      });
      
      // Ждем ответа от клиента
      socket.once('exit_confirmed', async () => {
        const user = await User.findById(socket.userId);
        const stats = await UserStats.findOne({ user_id: socket.userId });
        stats.lives = Math.max(0, stats.lives - 1);
        await stats.save();
        user.status = 'busy';
        await user.save();

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Бан за ранний выход из чата',
          text: 'Вы покинули чат раньше 5 минут и получили бан.'
        });
        socket.emit('banned_early_exit');
        
        socket.leave(socket.chatRoom);
        socket.chatRoom = null;
        socket.partnerId = null;
        clearTimeout(socket.disconnectTimer);
      });
      
      socket.once('exit_canceled', () => {
        // Пользователь отменил выход
      });
    } else {
      // Показываем подтверждение выхода без бана
      socket.emit('confirm_exit', {
        message: 'Вы действительно хотите прервать диалог?',
        roomId: socket.chatRoom,
        noBan: true
      });
      
      socket.once('exit_confirmed', async () => {
        // Уведомляем партнера о выходе
        io.to(socket.chatRoom).emit('partner_left_chat', { 
          userId: socket.userId 
        });
        
        socket.leave(socket.chatRoom);
        socket.chatRoom = null;
        socket.partnerId = null;
        clearTimeout(socket.disconnectTimer);
      });
    }
  });

  // Блок 73.3: разрыв соединения (обрыв интернета)
socket.on('disconnect', async () => {
  if (socket.chatRoom && socket.partnerId) {
    // Устанавливаем флаг ожидания партнера
    socket.waitingForPartner = true;
    
    // Запускаем таймер ожидания (5 минут)
    socket.disconnectTimer = setTimeout(async () => {
      const isStillOffline = !io.sockets.adapter.rooms.get(socket.chatRoom)?.has(socket.userId);
      if (isStillOffline) {
        const user = await User.findById(socket.userId);
        const stats = await UserStats.findOne({ user_id: socket.userId });
        stats.lives = Math.max(0, stats.lives - 1);
        await stats.save();
        user.status = 'busy';
        await user.save();

        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Бан за разрыв связи',
          text: 'Вы не вернулись в чат в течение 5 минут и получили бан.'
        });
      }
    }, 5 * 60 * 1000);

    // Уведомляем партнера о разрыве связи
    io.to(socket.chatRoom).emit('partner_disconnected', {
      waitingTime: 5 * 60 * 1000,
      userId: socket.userId
    });
  }

  // Обычный оффлайн-статус
  try {
    const user = await User.findById(socket.userId);
    user.status = 'busy';
    await user.save();
    io.to('onlineUsers').emit('userStatus', { userId: socket.userId, status: 'busy' });
    logger.info(`Пользователь ${socket.userId} отключился`);
  } catch (err) {
    logger.error('Ошибка отключения:', err);
  }
});

  // Блок 73.4: поиск собеседника
  socket.on('find_match', async () => {
    try {
      const user = await User.findById(socket.userId);
      if (!user || !user.emailVerified || !user.rulesAgreed || user.status === 'busy') {
        socket.emit('error', 'Недостаточно прав для подбора');
        return;
      }

      const messages = await Message.find({
        $or: [
          { sender_id: socket.userId },
          { receiver_id: socket.userId }
        ],
        created_at: { $gte: moment().subtract(72, 'hours') }
      });
      const excludeIds = messages.map(msg => msg.sender_id.equals(socket.userId) ? msg.receiver_id : msg.sender_id);

      const friendRequests = await FriendRequest.find({
        $or: [
          { from: socket.userId, status: 'accepted' },
          { to: socket.userId, status: 'accepted' }
        ]
      });
      const friendIds = friendRequests.map(fr => fr.from.equals(socket.userId) ? fr.to : fr.from);

      const potentialMatches = await User.find({
        _id: { $ne: socket.userId, $nin: excludeIds.concat(friendIds) },
        gender: user.preferredGender === 'any' ? { $in: ['male', 'female'] } : user.preferredGender,
        birthdate: {
          $gte: moment().subtract(user.preferredAgeMax + 1, 'years').toDate(),
          $lte: moment().subtract(user.preferredAgeMin, 'years').toDate()
        },
        status: 'online',
        emailVerified: true,
        rulesAgreed: true
      });

      if (potentialMatches.length === 0) {
        // Предлагаем ИИ-бота
        const roomId = `room:${socket.userId}:ai_bot`;
        socket.join(roomId);
        socket.emit('match_found', { 
          roomId, 
          to: 'AI Bot', 
          isBot: true 
        });
        return;
      }

      const match = potentialMatches[Math.floor(Math.random() * potentialMatches.length)];
      const roomId = `room:${socket.userId}:${match._id}`;
      socket.join(roomId);
      io.to(`user:${match._id}`).emit('match_found', { 
        roomId, 
        from: user.username 
      });
      socket.emit('match_found', { 
        roomId, 
        to: match.username 
      });
    } catch (err) {
      logger.error('Ошибка подбора собеседника:', err);
      socket.emit('error', 'Ошибка сервера');
    }
  });

  // Блок 73.5: отправка сообщения
socket.on('message', async ({ roomId, message, receiverId }) => {
  try {
    const user = await User.findById(socket.userId);
    if (!user) return socket.emit('error', 'Пользователь не найден');
    
    // Проверка на пустую болтовню
    const checkEmptyChat = (msg) => {
      const emptyPatterns = [
        /^[a-zA-Z]{1,3}$/, // Только 1-3 буквы
        /^[.,!?;:]{1,5}$/, // Только знаки препинания
        /^(Привет|Пока|Ок|Да|Нет)$/i // Общие короткие ответы
      ];
      return emptyPatterns.some(pattern => pattern.test(msg.trim()));
    };

    if (checkEmptyChat(message)) {
      const stats = await UserStats.findOne({ user_id: socket.userId });
      if (stats) {
        stats.emptyMessagesCount = (stats.emptyMessagesCount || 0) + 1;
        
        if (stats.emptyMessagesCount >= 5) {
          stats.lives = Math.max(0, stats.lives - 1);
          await stats.save();
          
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Предупреждение в CHOIZZE',
            text: 'Вы отправляете слишком много бессмысленных сообщений. Пожалуйста, ведите осмысленный диалог.'
          });
        } else {
          await stats.save();
        }
      }
    }
    
    // Если это ИИ-бот, обрабатываем specially
    if (receiverId === 'ai_bot') {
      // Здесь может быть логика для ответа ИИ-бота
      // Временно просто отправляем эхо-ответ
      const botResponse = `Вы сказали: "${message}". Это ответ ИИ-бота.`;
      
      io.to(roomId).emit('message', {
        sender: 'AI Bot',
        message: botResponse,
        timestamp: new Date(),
        isBot: true
      });
      return;
    }
    
    // Получаем информацию о получателе для перевода
    const receiver = await User.findById(receiverId);
    if (!receiver) return socket.emit('error', 'Получатель не найден');
    
    // Определяем язык получателя (в реальном приложении это должно храниться в профиле)
    const receiverLanguage = receiver.settings?.language || 'en';
    
    // Переводим сообщение, если языки отличаются
    let translatedMessage = message;
    if (user.settings?.language !== receiverLanguage) {
      translatedMessage = await translateMessage(message, receiverLanguage);
    }
    
    const msg = new Message({
      sender_id: socket.userId,
      receiver_id: receiverId,
      message_text: message,
      translated_text: translatedMessage,
      created_at: new Date()
    });
    await msg.save();
    
    io.to(roomId).emit('message', {
      sender: user.username,
      message: translatedMessage,
      originalMessage: message,
      timestamp: msg.created_at,
      senderId: socket.userId
    });
    
    // Звуковое уведомление для получателя
    io.to(`user:${receiverId}`).emit('new_message_sound');
  } catch (err) {
    logger.error('Ошибка отправки сообщения:', err);
    socket.emit('error', 'Ошибка сервера');
  }
});

  // Блок 73.6: звонок
  socket.on('call', async ({ roomId, receiverId }) => {
    try {
      const user = await User.findById(socket.userId);
      const receiver = await User.findById(receiverId);
      if (!receiver || receiver.status === 'busy') {
        await Message.create({
          sender_id: socket.userId,
          receiver_id: receiverId,
          message_text: 'call_missed'
        });
        const stats = await UserStats.findOne({ user_id: receiverId });
        stats.missed_calls += 1;
        if (stats.missed_calls >= 3) {
          stats.missed_calls = 0;
          await Report.create({
            reporterId: socket.userId,
            reportedId: receiverId,
            reason: 'Автоматический бан за 3 пропущенных звонка'
          });
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: receiver.email,
            subject: 'Бан за пропущенные звонки CHOIZZE',
            text: 'Вы забанены за 3 пропущенных звонка. Подайте апелляцию в разделе "История".'
          });
          receiver.status = 'busy';
          await receiver.save();
        }
        await stats.save();
        socket.emit('call_failed', 'Собеседник занят или недоступен');
        return;
      }
      
      // Звуковое уведомление о входящем звонке
      io.to(`user:${receiverId}`).emit('incoming_call_sound', {
        from: user.username,
        roomId
      });
      
      io.to(roomId).emit('call_incoming', { from: user.username });
    } catch (err) {
      logger.error('Ошибка звонка:', err);
      socket.emit('error', 'Ошибка сервера');
    }
  });

  // Блок 73.7: отказ от звонка
  socket.on('call_reject', async ({ roomId, callerId }) => {
    try {
      const stats = await UserStats.findOne({ user_id: socket.userId });
      stats.refused_calls += 1;
      if (stats.refused_calls >= 4) {
        stats.refused_calls = 0;
        await Report.create({
          reporterId: callerId,
          reportedId: socket.userId,
          reason: 'Автоматический бан за 4 отказа от звонков'
        });
        const user = await User.findById(socket.userId);
        user.status = 'busy';
        await user.save();
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Бан за отказ от звонков CHOIZZE',
          text: 'Вы забанены за 4 отказа от звонков. Подайте апелляцию в разделе "История".'
        });
      }
      await stats.save();
      io.to(roomId).emit('call_rejected', { from: socket.userId });
    } catch (err) {
      logger.error('Ошибка отказа от звонка:', err);
      socket.emit('error', 'Ошибка сервера');
    }
  });

  // Блок 73.8: завершение чата
socket.on('chat_end', async ({ roomId, receiverId }) => {
  try {
    const stats = await UserStats.findOne({ user_id: socket.userId });
    const duration = moment().diff(moment(socket.chatStart), 'seconds');
    if (duration >= 5 * 60) {
      const messages = await Message.find({
        $or: [
          { sender_id: socket.userId, receiver_id: receiverId },
          { sender_id: receiverId, receiver_id: socket.userId }
        ],
        created_at: { $gte: socket.chatStart }
      });
      if (messages.length > 0) {
        const chatMinutes = Math.floor(duration / 60);
        if (chatMinutes >= 6) {
          const hours = Math.floor((chatMinutes - 5) / 60);
          if (hours > 0 && stats.chat_hours_today < 10) {
            const hoursToAward = Math.min(hours, 10 - stats.chat_hours_today);
            stats.chat_hours_today += hoursToAward;
            stats.cp += hoursToAward * parseFloat(process.env.CP_PER_HOUR_CHAT);
            await stats.save();
            
            // Уведомление о достижении лимита
            if (stats.chat_hours_today >= 10) {
              const user = await User.findById(socket.userId);
              await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: 'Лимит CP за общение CHOIZZE',
                text: 'Вы достигли лимита 10 часов общения за сутки. CP начнут начисляться снова завтра.'
              });
            }
          }
        }
      }
    }
    socket.chatStart = null;
  } catch (err) {
    logger.error('Ошибка завершения чата:', err);
  }
});

  // Блок 73.9: присоединение к чату
  socket.on('joinChat', async () => {
    try {
      const user = await User.findById(socket.userId);
      user.status = 'online';
      await user.save();
      socket.join('onlineUsers');
      io.to('onlineUsers').emit('userStatus', { userId: socket.userId, status: 'online' });
    } catch (err) {
      logger.error('Ошибка присоединения к чату:', err);
    }
  });

  // Блок 73.10: отправка сообщения другу
  socket.on('sendMessage', async (data) => {
    try {
      const { receiverId, messageText } = data;
      const sender = await User.findById(socket.userId);
      if (!sender.emailVerified || !sender.rulesAgreed) {
        return socket.emit('error', { message: 'Подтвердите email и примите правила' });
      }
      const receiver = await User.findById(receiverId);
      if (!receiver) {
        return socket.emit('error', { message: 'Получатель не найден' });
      }
      
      // Перевод сообщения, если языки отличаются
      let translatedMessage = messageText;
      if (sender.settings?.language !== receiver.settings?.language) {
        translatedMessage = await translateMessage(messageText, receiver.settings?.language || 'en');
      }
      
      const message = new Message({
        sender_id: socket.userId,
        receiver_id: receiverId,
        message_text: messageText,
        translated_text: translatedMessage
      });
      await message.save();
      
      io.to(receiverId.toString()).emit('receiveMessage', {
        senderId: socket.userId,
        messageText: translatedMessage,
        originalMessage: messageText,
        createdAt: message.created_at
      });
      
      // Звуковое уведомление
      io.to(receiverId.toString()).emit('new_message_sound');
      
      const stats = await UserStats.findOne({ user_id: socket.userId });
      stats.total_online_time += 1;
      if (stats.total_online_time % 60 === 0) {
        stats.cp += 11.8;
        if (stats.total_online_time >= 600) {
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: sender.email,
            subject: 'Лимит наград за общение в CHOIZZE',
            text: 'Вы достигли лимита наград за общение в этом месяце. Бонусы начнут начисляться в следующем месяце.'
          });
        }
      }
      await stats.save();
    } catch (err) {
      logger.error('Ошибка отправки сообщения:', err);
      socket.emit('error', { message: 'Ошибка сервера' });
    }
  });
  
  // Блок 73.11: изменение статуса пользователя
  socket.on('change_status', async ({ status }) => {
    try {
      const user = await User.findById(socket.userId);
      user.status = status;
      await user.save();
      io.to('onlineUsers').emit('userStatus', { userId: socket.userId, status });
    } catch (err) {
      logger.error('Ошибка изменения статуса:', err);
      socket.emit('error', { message: 'Ошибка сервера' });
    }
  });
});

// Блок 74: Получение списка пользователей
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } }).select('username status');
    res.json(users);
  } catch (err) {
    logger.error('Ошибка получения списка пользователей:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 75: Получение профиля другого пользователя
app.get('/api/users/:id', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('username gender birthdate style');
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    res.json(user);
  } catch (err) {
    logger.error('Ошибка получения профиля пользователя:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 76: Получение профиля текущего пользователя
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    const stats = await UserStats.findOne({ user_id: req.userId });
    
    // Рассчитываем оставшееся время подписки
    const now = new Date();
    let subscriptionTimeLeft = null;
    if (user.subscriptionExpiresAt > now) {
      const diffMs = user.subscriptionExpiresAt - now;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
      
      if (diffDays > 0) {
        subscriptionTimeLeft = `${diffDays}:${diffHours.toString().padStart(2, '0')}:${diffMinutes.toString().padStart(2, '0')}`;
      } else {
        subscriptionTimeLeft = `${diffHours}:${diffMinutes.toString().padStart(2, '0')}`;
      }
    }
    
    res.json({
      user,
      stats,
      subscriptionTimeLeft
    });
  } catch (err) {
    logger.error('Ошибка получения профиля:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 77: Получение списка жалоб (для админов)
app.get('/api/admin/reports', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user.isAdmin) {
      return res.status(403).json({ error: 'Доступ запрещён' });
    }
    const reports = await Report.find().populate('reporterId reportedId', 'username');
    res.json(reports);
  } catch (err) {
    logger.error('Ошибка получения списка жалоб:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 78: Обработка жалобы (для админов)
app.put('/api/admin/report/:reportId', verifyToken, [
  check('action').isIn(['ban', 'dismiss']).withMessage('Недопустимое действие')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  try {
    const { reportId } = req.params;
    const { action } = req.body;
    const admin = await User.findById(req.userId);
    if (!admin.isAdmin) {
      return res.status(403).json({ error: 'Доступ запрещён' });
    }
    const report = await Report.findById(reportId);
    if (!report) {
      return res.status(404).json({ error: 'Жалоба не найдена' });
    }
    if (action === 'ban') {
      const user = await User.findById(report.reportedId);
      user.status = 'busy';
      await user.save();
      const stats = await UserStats.findOne({ user_id: report.reportedId });
      stats.lives -= 1;
      await stats.save();
    }
    report.status = action === 'ban' ? 'accepted' : 'dismissed';
    await report.save();
    res.json({ message: `Жалоба ${action === 'ban' ? 'принята, пользователь заблокирован' : 'отклонена'}` });
  } catch (err) {
    logger.error('Ошибка обработки жалобы:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 79: Проверка неактивности
cron.schedule('0 0 * * *', async () => {
  try {
    const users = await User.find({ emailVerified: true, rulesAgreed: true });
    for (const user of users) {
      const stats = await UserStats.findOne({ user_id: user._id });
      if (moment().diff(stats.last_online, 'days') >= 7) {
        await transporter.sendMail({
          from: process.env.EMAIL_USER,
          to: user.email,
          subject: 'Неактивность в CHOIZZE',
          text: 'Вы не заходили в приложение более 7 дней. Зайдите, чтобы не потерять доступ!'
        });
      }
      if (moment().diff(stats.daily_reset, 'days') >= 1) {
        stats.chat_hours_today = 0;
        stats.daily_reset = new Date();
        await stats.save();
      }
      if (moment().diff(stats.daily_reset, 'days') >= 1) {
  stats.chat_hours_today = 0;
  stats.referralsToday = 0; // Добавить эту строку
  stats.daily_reset = new Date();
  await stats.save();
      }
      if (moment().diff(stats.monthly_reset, 'days') >= 30) {
        stats.monthly_appeals = 0;
        stats.monthly_reset = new Date();
        await stats.save();
      }
    }
  } catch (err) {
    logger.error('Ошибка проверки неактивности:', err);
  }
});

// Блок 79.1: Ежечасная проверка активности (ТЗ 2.5.1)
cron.schedule('0 * * * *', async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const users = await User.find({ status: 'online', emailVerified: true, rulesAgreed: true });

    for (const user of users) {
      const stats = await UserStats.findOne({ user_id: user._id });
      if (!stats) continue;

      // Проверяем, был ли пользователь активен за последний час
      if (!stats.chatCompleted || stats.lastChatStart < oneHourAgo) {
        const warnings = await UserActivity.findOne({ userId: user._id, type: 'inactivity_warning' });

        if (!warnings || warnings.count < 3) {
          // Отправляем уведомление
          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Будьте активны в CHOIZZE',
            text: 'Будьте активны: поговорите хотя бы раз в час или переведите статус в «Занят».'
          });

          // Увеличиваем счетчик предупреждений
          await UserActivity.findOneAndUpdate(
            { userId: user._id, type: 'inactivity_warning' },
            { $inc: { count: 1 }, lastWarning: new Date() },
            { upsert: true, new: true }
          );
        } else {
          // После 3-го предупреждения – бан
          stats.lives = Math.max(0, stats.lives - 1);
          user.status = 'busy';
          await user.save();
          await stats.save();

          await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Бан за неактивность в CHOIZZE',
            text: 'Вы получили бан за неактивность. Подайте апелляцию в разделе "История".'
          });

          // Сброс счетчика
          await UserActivity.deleteOne({ userId: user._id, type: 'inactivity_warning' });
        }
      }

      stats.lastActivityCheck = new Date();
      await stats.save();
    }
  } catch (err) {
    logger.error('Ошибка проверки активности:', err);
  }
});

// Блок 79.2: Ежечасная генерация викторин (ТЗ 2.4)
cron.schedule('0 * * * *', async () => {
  try {
    const now = new Date();
    const hour = now.getHours();

    // Спрятанные слова (каждый час)
    const hiddenWords = ['солнце', 'дружба', 'мечта', 'сердце', 'улыбка', 'надежда', 'любовь', 'счастье'];
    const word = hiddenWords[Math.floor(Math.random() * hiddenWords.length)];
    await Quiz.create({
      type: 'hidden_words',
      content: `Найдите слово: ${word}`,
      correct_answer: word,
      userId: null // системная викторина
    });

    // Логическая сборка (каждый 3-й час)
    if (hour % 3 === 0) {
      const facts = [
        'Факт 1: Вода кипит при 100°C',
        'Факт 2: Свет распространяется со скоростью 300 000 км/с',
        'Факт 3: Земля вращается вокруг Солнца за 365 дней'
      ];
      const logicAnswer = facts.join(' ');
      await Quiz.create({
        type: 'logic_assembly',
        content: facts.join('. '),
        correct_answer: logicAnswer,
        userId: null
      });
    }

    // Живое взаимодействие (каждый 6-й час)
    if (hour % 6 === 0) {
      const interactionWords = ['добро', 'тепло', 'искренность', 'понимание', 'уважение'];
      const interactionPhrase = interactionWords.join(' ');
      await Quiz.create({
        type: 'live_interaction',
        content: interactionPhrase,
        correct_answer: interactionPhrase,
        userId: null
      });
    }

    // Мгновенная реакция (каждый час)
    const reactionQuestion = `Что делает человека счастливым?`;
    const reactionAnswer = `общение`;
    await Quiz.create({
      type: 'instant_reaction',
      content: reactionQuestion,
      correct_answer: reactionAnswer,
      userId: null
    });

    logger.info(`Викторины сгенерированы в ${hour}:00`);
  } catch (err) {
    logger.error('Ошибка генерации викторин:', err);
  }
});

// Блок 79.3: ежедневные push/email уведомления для вовлечения
cron.schedule('0 10 * * *', async () => {
  try {
    const inactiveDays = 3; // считаем неактивными после 3 дней
    const inactiveUsers = await User.find({
      emailVerified: true,
      rulesAgreed: true,
      last_online: { $lt: new Date(Date.now() - inactiveDays * 24 * 60 * 60 * 1000) }
    });

    for (const user of inactiveUsers) {
      const stats = await UserStats.findOne({ user_id: user._id });

      // Генерируем выдуманную статистику
      const fakeStats = {
        missedChats: Math.floor(Math.random() * 901) + 100, // 100-1000
        newUsers: Math.floor(Math.random() * 50) + 10,
        popularTime: ['утром', 'днём', 'вечером'][Math.floor(Math.random() * 3)]
      };

      // Email уведомление
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: 'Вас ждут в CHOIZZE!',
        html: `
<h2>Привет, ${user.username}!</h2>
<p>За последние 3 дня:</p>
<ul>
  <li>🔥 <b>${fakeStats.missedChats}</b> человек хотели поговорить именно с тобой!</li>
  <li>👥 <b>${fakeStats.newUsers}</b> новых интересных людей присоединились</li>
  <li>⏰ Самое активное время: ${fakeStats.popularTime}</li>
</ul>
<p><a href="http://localhost:${process.env.PORT}">Вернуться к общению →</a></p>
<p><small>Это автоматическое письмо. Отписаться можно в настройках.</small></p>
`
      });

      // Push-уведомление для веб (через Socket.IO)
      io.to(`user:${user._id}`).emit('push_notification', {
        title: 'Вас ждут в CHOIZZE!',
        body: `${fakeStats.missedChats} человек хотели с вами поговорить`,
        icon: '/assets/notification-icon.png',
        url: '/'
      });
    }

    logger.info(`Отправлено ${inactiveUsers.length} уведомлений неактивным пользователям`);
  } catch (err) {
    logger.error('Ошибка отправки уведомлений:', err);
  }
});

// Блок 80: Получение ленты новостей
app.get('/api/feed', verifyToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    const posts = await Post.find()
      .populate('userId', 'username')
      .populate({
        path: 'comments',
        populate: { path: 'userId', select: 'username' }
      })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    
    res.json(posts);
  } catch (err) {
    logger.error('Ошибка получения ленты новостей:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 81: Получение настроек пользователя
app.get('/api/settings', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('settings');
    if (!user.settings) {
      // Создаем настройки по умолчанию, если их нет
      user.settings = {
        notifications: true,
        language: 'ru',
        theme: 'light'
      };
      await user.save();
    }
    res.json(user.settings);
  } catch (err) {
    logger.error('Ошибка получения настроек:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 82: Обновление настроек пользователя
app.put('/api/settings', verifyToken, async (req, res) => {
  try {
    const { notifications, language, theme } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user.settings) {
      user.settings = {};
    }
    
    if (notifications !== undefined) user.settings.notifications = notifications;
    if (language !== undefined) user.settings.language = language;
    if (theme !== undefined) user.settings.theme = theme;
    
    await user.save();
    res.json({ message: 'Настройки обновлены', settings: user.settings });
  } catch (err) {
    logger.error('Ошибка обновления настроек:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 83: Выход из системы
app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    // В реальном приложении здесь может быть добавление токена в черный список
    res.json({ message: 'Вы успешно вышли из системы' });
  } catch (err) {
    logger.error('Ошибка выхода из системы:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 84: Получение текущих викторин
app.get('/api/quizzes', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    // Проверка доступа к викторинам
    if (!user.isPaid && user.subscriptionExpiresAt < new Date()) {
      return res.status(403).json({ error: 'Доступ к викторинам ограничен' });
    }
    
    const quizzes = await Quiz.find({
      $or: [
        { userId: null },
        { userId: req.userId }
      ],
      status: 'active'
    }).sort({ createdAt: -1 });
    
    res.json(quizzes);
  } catch (err) {
    logger.error('Ошибка получения викторин:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 85: Отправка ответа на викторину
app.post('/api/quizzes/:id/answer', verifyToken, async (req, res) => {
  try {
    const { answer } = req.body;
    const quizId = req.params.id;
    
    const quiz = await Quiz.findById(quizId);
    if (!quiz) {
      return res.status(404).json({ error: 'Викторина не найдена' });
    }
    
    const user = await User.findById(req.userId);
    
    // Проверка, что у пользователя есть время для участия в викторинах
    if (user.subscriptionExpiresAt < new Date() && !user.isPaid) {
      return res.status(403).json({ error: 'Время для участия в викторинах истекло' });
    }
    
    // Проверяем, не отвечал ли пользователь уже на эту викторину
    const existingAnswer = await Quiz.findOne({
      _id: quizId,
      userId: req.userId,
      status: 'completed'
    });
    
    if (existingAnswer) {
      return res.status(400).json({ error: 'Вы уже отвечали на эту викторину' });
    }
    
    // Проверяем ответ
    const isCorrect = answer.toLowerCase() === quiz.correct_answer.toLowerCase();
    
    if (isCorrect) {
      // Начисляем CP в зависимости от типа викторины
      const stats = await UserStats.findOne({ user_id: req.userId });
      let cpEarned = 0;
      
      switch (quiz.type) {
        case 'hidden_words': cpEarned = parseFloat(process.env.CP_QUIZ_WORDS); break;
        case 'live_interaction': cpEarned = parseFloat(process.env.CP_QUIZ_INTERACTION); break;
        case 'instant_reaction': cpEarned = parseFloat(process.env.CP_QUIZ_REACTION); break;
        case 'logic_assembly': cpEarned = parseFloat(process.env.CP_QUIZ_LOGIC); break;
      }
      
      stats.cp += cpEarned;
      await stats.save();
      
      // Обновляем статус викторины
      quiz.status = 'completed';
      quiz.userId = req.userId;
      quiz.completedAt = new Date();
      await quiz.save();
      
      res.json({ 
        message: 'Правильный ответ! CP начислены', 
        cpEarned,
        correct: true 
      });
    } else {
      res.json({ 
        message: `Неправильный ответ. Правильный ответ: ${quiz.correct_answer}`, 
        correct: false 
      });
    }
  } catch (err) {
    logger.error('Ошибка отправки ответа на викторину:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 86: Активация полного доступа после 200 реклам
app.post('/api/activate-full-access', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const stats = await UserStats.findOne({ user_id: req.userId });
    
    if (stats.ad_views < 200) {
      return res.status(400).json({ error: 'Вы еще не просмотрели 200 реклам' });
    }
    
    if (user.fullAccessActivated) {
      return res.status(400).json({ error: 'Полный доступ уже активирован' });
    }
    
    user.isPaid = true;
    user.subscriptionExpiresAt = moment().add(30, 'days').toDate();
    user.fullAccessActivated = true;
    stats.lives = 3;
    stats.banChips = 15;
    
    await user.save();
    await stats.save();
    
    res.json({ message: 'Полный доступ успешно активирован на 30 дней!' });
  } catch (err) {
    logger.error('Ошибка активации полного доступа:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 87: Получение списка друзей
app.get('/api/friends', verifyToken, async (req, res) => {
  try {
    const friendRequests = await FriendRequest.find({
      $or: [{ from: req.userId }, { to: req.userId }],
      status: 'accepted'
    }).populate('from to', 'username');
    
    const friends = friendRequests.map(fr => {
      const friend = fr.from._id.equals(req.userId) ? fr.to : fr.from;
      return {
        id: friend._id,
        username: friend.username
      };
    });
    
    res.json(friends);
  } catch (err) {
    logger.error('Ошибка получения списка друзей:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 88: Отправка запроса в друзья
app.post('/api/friends/request', verifyToken, async (req, res) => {
  try {
    const { friendId } = req.body;
    
    // Проверяем, не отправляли ли уже запрос
    const existingRequest = await FriendRequest.findOne({
      $or: [
        { from: req.userId, to: friendId },
        { from: friendId, to: req.userId }
      ],
      status: { $in: ['pending', 'accepted'] }
    });
    
    if (existingRequest) {
      return res.status(400).json({ error: 'Запрос в друзья уже отправлен или вы уже друзья' });
    }
    
    const friendRequest = new FriendRequest({
      from: req.userId,
      to: friendId,
      status: 'pending'
    });
    
    await friendRequest.save();
    
    // Уведомляем пользователя о запросе
    io.to(`user:${friendId}`).emit('friend_request', {
      from: req.userId,
      username: (await User.findById(req.userId)).username
    });
    
    res.json({ message: 'Запрос в друзья отправлен' });
  } catch (err) {
    logger.error('Ошибка отправки запроса в друзья:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 89: Принятие или отклонение запроса в друзья
app.put('/api/friends/request/:requestId', verifyToken, async (req, res) => {
  try {
    const { status } = req.body; // 'accepted' или 'rejected'
    const requestId = req.params.requestId;
    
    const friendRequest = await FriendRequest.findById(requestId);
    if (!friendRequest) {
      return res.status(404).json({ error: 'Запрос не найден' });
    }
    
    if (friendRequest.to.toString() !== req.userId) {
      return res.status(403).json({ error: 'Вы не можете обработать этот запрос' });
    }
    
    friendRequest.status = status;
    await friendRequest.save();
    
    if (status === 'accepted') {
      // Уведомляем пользователя о принятии запроса
      io.to(`user:${friendRequest.from}`).emit('friend_request_accepted', {
        to: req.userId,
        username: (await User.findById(req.userId)).username
      });
    }
    
    res.json({ message: `Запрос ${status === 'accepted' ? 'принят' : 'отклонен'}` });
  } catch (err) {
    logger.error('Ошибка обработки запроса в друзья:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 90: Удаление из друзей
app.delete('/api/friends/:friendId', verifyToken, async (req, res) => {
  try {
    const friendId = req.params.friendId;
    
    const friendRequest = await FriendRequest.findOneAndDelete({
      $or: [
        { from: req.userId, to: friendId },
        { from: friendId, to: req.userId }
      ],
      status: 'accepted'
    });
    
    if (!friendRequest) {
      return res.status(404).json({ error: 'Пользователь не найден в списке друзей' });
    }
    
    res.json({ message: 'Пользователь удален из списка друзей' });
  } catch (err) {
    logger.error('Ошибка удаления из друзей:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 91: Получение истории жизней
app.get('/api/lives-history', verifyToken, async (req, res) => {
  try {
    // История банов
    const bansGiven = await Report.find({ reporterId: req.userId })
      .populate('reportedId', 'username')
      .sort({ createdAt: -1 });
    
    const bansReceived = await Report.find({ reportedId: req.userId })
      .populate('reporterId', 'username')
      .sort({ createdAt: -1 });
    
    // История чатов
    const chats = await Message.find({
      $or: [{ sender_id: req.userId }, { receiver_id: req.userId }],
      created_at: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    })
    .populate('sender_id receiver_id', 'username')
    .sort({ created_at: -1 });
    
    // История запросов в друзья
    const friendRequests = await FriendRequest.find({
      $or: [{ from: req.userId }, { to: req.userId }],
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }
    })
    .populate('from to', 'username')
    .sort({ createdAt: -1 });
    
    // Формируем историю
    const history = [];
    
    // Добавляем успешные чаты
    chats.forEach(chat => {
      const partner = chat.sender_id._id.equals(req.userId) ? chat.receiver_id : chat.sender_id;
      history.push({
        type: 'chat',
        partner: partner.username,
        date: chat.created_at,
        success: true
      });
    });
    
    // Добавляем баны от меня
    bansGiven.forEach(ban => {
      history.push({
        type: 'ban_given',
        partner: ban.reportedId.username,
        date: ban.createdAt,
        reason: ban.reason
      });
    });
    
    // Добавляем баны на меня
    bansReceived.forEach(ban => {
      history.push({
        type: 'ban_received',
        partner: ban.reporterId.username,
        date: ban.createdAt,
        reason: ban.reason,
        hasAppeal: ban.status === 'pending'
      });
    });
    
    // Добавляем запросы в друзья
    friendRequests.forEach(request => {
      const partner = request.from._id.equals(req.userId) ? request.to : request.from;
      const isSent = request.from._id.equals(req.userId);
      
      history.push({
        type: isSent ? 'friend_request_sent' : 'friend_request_received',
        partner: partner.username,
        date: request.createdAt,
        status: request.status
      });
    });
    
    // Сортируем по дате
    history.sort((a, b) => b.date - a.date);
    
    res.json(history);
  } catch (err) {
    logger.error('Ошибка получения истории жизней:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 92: Получение статистики CP
app.get('/api/cp-stats', verifyToken, async (req, res) => {
  try {
    const stats = await UserStats.findOne({ user_id: req.userId });
    const user = await User.findById(req.userId);
    
    // Рассчитываем оставшееся время подписки
    const now = new Date();
    let subscriptionTimeLeft = null;
    if (user.subscriptionExpiresAt > now) {
      const diffMs = user.subscriptionExpiresAt - now;
      const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
      
      if (diffDays > 0) {
        subscriptionTimeLeft = `${diffDays}:${diffHours.toString().padStart(2, '0')}:${diffMinutes.toString().padStart(2, '0')}`;
      } else {
        subscriptionTimeLeft = `${diffHours}:${diffMinutes.toString().padStart(2, '0')}`;
      }
    }
    
    res.json({
      cp: stats.cp,
      lives: stats.lives,
      banChips: stats.banChips,
      ad_views: stats.ad_views,
      adsToFullAccess: Math.max(0, 200 - stats.ad_views),
      subscriptionTimeLeft,
      isPaid: user.isPaid,
      fullAccessActivated: user.fullAccessActivated || false
    });
  } catch (err) {
    logger.error('Ошибка получения статистики CP:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 93: Запрос на вывод CP
app.post('/api/withdraw', verifyToken, [
  check('amount').isFloat({ min: 100 }).withMessage('Минимальная сумма вывода 100 CP'),
  check('wallet').notEmpty().withMessage('Укажите кошелек для вывода'),
  check('method').isIn(['paypal', 'payeer', 'bitcoin']).withMessage('Недопустимый метод вывода')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  try {
    const { amount, wallet, method } = req.body;
    const stats = await UserStats.findOne({ user_id: req.userId });
    
    if (stats.cp < amount) {
      return res.status(400).json({ error: 'Недостаточно CP для вывода' });
    }
    
    // Создаем запрос на вывод
    const withdrawal = new Withdrawal({
      userId: req.userId,
      amount,
      wallet,
      method,
      status: 'pending',
      createdAt: new Date()
    });
    
    await withdrawal.save();
    
    // Резервируем CP
    stats.cp -= amount;
    stats.reservedCp = (stats.reservedCp || 0) + amount;
    await stats.save();
    
    res.json({ 
      message: 'Запрос на вывод создан. Средства будут переведены после проверки.',
      withdrawalId: withdrawal._id 
    });
  } catch (err) {
    logger.error('Ошибка создания запроса на вывод:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 94: Получение истории выводов
app.get('/api/withdrawals', verifyToken, async (req, res) => {
  try {
    const withdrawals = await Withdrawal.find({ userId: req.userId })
      .sort({ createdAt: -1 });
    
    res.json(withdrawals);
  } catch (err) {
    logger.error('Ошибка получения истории выводов:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 95: Проверка и создание поля settings у пользователя
app.use(async (req, res, next) => {
  if (req.user && req.user.id) {
    try {
      const user = await User.findById(req.user.id);
      if (user && !user.settings) {
        user.settings = {
          notifications: true,
          language: 'ru',
          theme: 'light'
        };
        await user.save();
      }
    } catch (err) {
      console.error('Ошибка при проверке настроек пользователя:', err);
    }
  }
  next();
});

// Блок 96: Главная страница
app.get('/api/homepage', (req, res) => {
  try {
    const aboutData = require('../about.json');
    res.json({
      header: "Добро пожаловать в CHOIZZE",
      body: aboutData.content,
      footer: "© 2023 CHOIZZE"
    });
  } catch (err) {
    logger.error('Ошибка чтения файла about.json:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 97: Обратная связь
app.post('/api/contact', [
  check('name').notEmpty().withMessage('Укажите имя'),
  check('email').isEmail().withMessage('Неверный email'),
  check('message').notEmpty().withMessage('Введите сообщение')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  
  try {
    const { name, email, message } = req.body;
    
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      subject: 'Новое сообщение обратной связи CHOIZZE',
      text: `Имя: ${name}\nEmail: ${email}\nСообщение: ${message}`
    });
    
    res.json({ message: 'Сообщение отправлено' });
  } catch (err) {
    logger.error('Ошибка отправки обратной связи:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 98: О проекте
app.get('/api/about', (req, res) => {
  try {
    const aboutData = require('../about.json');
    res.json(aboutData);
  } catch (err) {
    logger.error('Ошибка чтения файла about.json:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 99: Авторизация
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }
    if (!user.emailVerified) {
      return res.status(403).json({ error: 'Подтвердите email' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token });
  } catch (err) {
    logger.error('Ошибка входа:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Блок 101: Глобальная обработка ошибок
app.use((err, req, res, next) => {
  logger.error(err.stack);
  
  // Ошибки валидации
  if (err.name === 'ValidationError') {
    return res.status(400).json({ 
      error: 'Ошибка валидации данных',
      details: err.message 
    });
  }
  
  // Ошибки JWT
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Недействительный токен' });
  }
  
  // Ошибки MongoDB
  if (err.name === 'MongoError') {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Дубликат данных' });
    }
  }
  
  // Ошибки внешних API
  if (err.isAxiosError) {
    return res.status(502).json({ error: 'Ошибка внешнего сервиса' });
  }
  
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// Обработка 404
app.use((req, res) => {
  res.status(404).json({ error: 'Страница не найдена' });
});

// Блок 102: Применение ограничений запросов
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // максимум 100 запросов
  message: 'Слишком много запросов с вашего IP, попробуйте позже'
});

// Применяем ко всем запросам
app.use(limiter);

// Блок 103: Обработка ошибок внешних сервисов
// Обработка ошибок TronWeb
try {
  tronWeb.setHeader({ "TRON-PRO-API-KEY": process.env.TRONGRID_API_KEY });
  tronWeb.setAddress("https://api.trongrid.io");
} catch (err) {
  logger.error('Ошибка подключения к TronGrid:', err);
}

// Обработка ошибок перевода
const safeTranslate = async (text, targetLang) => {
  try {
    return await translateMessage(text, targetLang);
  } catch (err) {
    logger.error('Ошибка перевода:', err);
    return text; // Возвращаем оригинал при ошибке
  }
};

// Парсер новостей каждые 60 минут
cron.schedule('0 * * * *', async () => {
  try {
    const sources = await RSSSource.find({ isActive: true });
    
    for (const source of sources) {
      try {
        const response = await axios.get(source.url);
        const posts = parseRss(response.data);
        
        for (const post of posts) {
          const exists = await Post.findOne({ content: post.content });
          if (!exists) {
            await new Post({
              userId: null,
              content: `${post.content}\n\n[Автоматически сгенерировано]`,
              isAutoGenerated: true
            }).save();
          }
        }
        
        source.lastFetched = new Date();
        await source.save();
      } catch (err) {
        logger.error(`Ошибка парсинга RSS ${source.name}:`, err);
      }
    }
  } catch (err) {
    logger.error('Ошибка генерации постов:', err);
  }
});

function parseRss(xmlData) {
  // Здесь реализация парсинга RSS
  return [];
}

// Блок 000: Проверка платежей PAYEER через CSV

// cron уже импортирован ранее, используем существующий
cron.schedule('*/5 * * * *', async () => {
  try {
    // Ищем все платежи со статусом pending и методом payeer
    const pendingPayments = await Payment.find({ method: 'payeer', status: 'pending' });
    if (pendingPayments.length === 0) return;

    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();

    try {
      // Переход на страницу входа PAYEER
      await page.goto('https://payeer.com/', { waitUntil: 'networkidle2' });
      
      // Клик по кнопке входа
      await page.waitForSelector('body > section.section.section__first.section_gradient.section_hidden.tp_rm > div > div.intro > div > div:nth-child(1) > div > a.button.button_empty > span');
      await page.click('body > section.section.section__first.section_gradient.section_hidden.tp_rm > div > div.intro > div > div:nth-child(1) > div > a.button.button_empty > span');
      
      // Ввод логина
      await page.waitForSelector('#login-step1 > div > div.login-form__content > form > div:nth-child(10) > input[type=text]');
      await page.type('#login-step1 > div > div.login-form__content > form > div:nth-child(10) > input[type=text]', 'P1080587274');
      
      // Ввод пароля
      await page.waitForSelector('#login-step1 > div > div.login-form__content > form > div:nth-child(11) > input[type=password]');
      await page.type('#login-step1 > div > div.login-form__content > form > div:nth-child(11) > input[type=password]', '5KwuR7dK');
      
      // Нажатие кнопки входа
      await page.click('#login-step1 > div > div.login-form__content > form > button[type=submit]');
      await page.waitForNavigation({ waitUntil: 'networkidle2' });

      // Переход в раздел операций
      await page.waitForSelector('body > div.page.w.wleftmini1 > main > div > aside > div.menu > ul:nth-child(1) > li.time > a > i');
      await page.click('body > div.page.w.wleftmini1 > main > div > aside > div.menu > ul:nth-child(1) > li.time > a > i');
      
      // Скачивание CSV-файла
      await page.waitForSelector('#tab-myoperations > div.filter-action > a.link.export_csv > span');
      await page.click('#tab-myoperations > div.filter-action > a.link.export_csv > span');
      await page.waitForTimeout(5000); // Ожидание загрузки файла

      // Путь к скачанному файлу
      const downloadPath = path.join(require('os').homedir(), 'Downloads', 'history_25.08.2025_21.11.49.csv');
      if (!fs.existsSync(downloadPath)) {
        logger.warn('CSV файл не найден');
        return;
      }

      // Чтение и обработка CSV-файла
      fs.createReadStream(downloadPath)
        .pipe(csv({ separator: ';' }))
        .on('data', async (row) => {
          const comment = row['Description']?.replace(/"/g, '').trim();
          const amount = parseFloat(row['Credit']?.replace(',', '.') || '0');

          // Ищем платежи с суммой ровно 1.00
          if (amount === 1.00) {
            // Ищем совпадение по коду платежа
            const match = pendingPayments.find(p => comment === p.code.slice(0, 12));
            if (match) {
              // Обновляем статус платежа
              match.status = 'completed';
              await match.save();

              // Обновляем данные пользователя
              const user = await User.findById(match.userId);
              user.isPaid = true;
              user.subscriptionExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // +30 дней
              await user.save();

              // Обновляем статистику пользователя
              const stats = await UserStats.findOne({ user_id: user._id });
              if (stats) {
                stats.lives = 3;
                stats.banChips = 15;
                await stats.save();
              }

              // Отправляем уведомление на email
              await transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: '✅ Доступ активирован — CHOIZZE',
                text: `Ваш платёж через PAYEER подтверждён. Полный доступ активирован на 30 дней.`
              });

              logger.info(`✅ PAYEER оплата подтверждена для ${user.username}`);
            }
          }
        })
        .on('end', () => {
          // Удаляем CSV-файл после обработки
          fs.unlinkSync(downloadPath);
          logger.info('Обработка CSV-файла завершена');
        });
    } catch (err) {
      logger.error('Ошибка в процессе проверки PAYEER:', err);
    } finally {
      await browser.close();
    }
  } catch (err) {
    logger.error('Ошибка проверки платежей PAYEER:', err);
  }
});

// Запуск сервера
server.listen(PORT, () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});