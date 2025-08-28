const jwt = require('jsonwebtoken');
const winston = require('winston');

const logger = winston.createLogger({
  level: 'error',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log' })
  ]
});

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Получаем токен из заголовка
  if (!token) {
    logger.error('Токен не предоставлен');
    return res.status(401).json({ error: 'Токен не предоставлен' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    logger.error('Ошибка верификации токена:', err);
    return res.status(403).json({ error: 'Недействительный токен' });
  }
};

module.exports = verifyToken;