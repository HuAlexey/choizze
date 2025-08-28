const { TronWeb } = require('tronweb'); // Исправляем импорт
require('dotenv').config();

const tronWeb = new TronWeb({
  fullHost: 'https://api.trongrid.io',
  headers: { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY }
});

async function testTronWeb() {
  try {
    const nodeInfo = await tronWeb.trx.getNodeInfo();
    console.log('TronWeb инициализирован, информация о ноде:', JSON.stringify(nodeInfo, null, 2));
  } catch (err) {
    console.error('Ошибка инициализации TronWeb:', err.message);
  }
}

testTronWeb();