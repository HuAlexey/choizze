const rateLimit = require('express-rate-limit');

// Ограничение: 100 запросов с одного IP за 15 минут
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // Максимум 100 запросов
  message: 'Слишком много запросов, попробуйте снова через 15 минут'
});

module.exports = limiter;