const express = require('express');
const router = express.Router();
const handleCallRefusal = require('../middleware/handleCallRefusal');
const verifyToken = require('../models/verifyToken'); // Исправлен путь

router.post('/refuseCall', verifyToken, handleCallRefusal, async (req, res) => {
  res.status(200).json({ message: 'Отказ от звонка зарегистрирован' });
});

module.exports = router;