const mongoose = require('mongoose');

const appealSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  reportId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Report', 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  status: { 
    type: String, 
    default: 'pending',
    enum: ['pending', 'approved', 'rejected'] 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

module.exports = mongoose.model('Appeal', appealSchema);