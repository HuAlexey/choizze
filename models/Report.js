const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  reporterId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  reportedId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  reason: { 
    type: String, 
    required: true 
  },
  status: { 
    type: String, 
    default: 'pending',
    enum: ['pending', 'resolved', 'accepted', 'dismissed'] 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

module.exports = mongoose.model('Report', reportSchema);