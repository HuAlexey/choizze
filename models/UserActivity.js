const mongoose = require('mongoose');

const userActivitySchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  type: { 
    type: String, 
    required: true 
  },
  count: { 
    type: Number, 
    default: 0 
  },
  lastWarning: { 
    type: Date, 
    default: Date.now 
  }
});

module.exports = mongoose.model('UserActivity', userActivitySchema);