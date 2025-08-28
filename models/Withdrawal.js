const mongoose = require('mongoose');

const withdrawalSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  amount: { 
    type: Number, 
    required: true 
  },
  wallet: { 
    type: String, 
    required: true 
  },
  method: { 
    type: String, 
    required: true,
    enum: ['paypal', 'payeer', 'bitcoin']
  },
  status: { 
    type: String, 
    default: 'pending',
    enum: ['pending', 'completed', 'rejected']
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

module.exports = mongoose.model('Withdrawal', withdrawalSchema);