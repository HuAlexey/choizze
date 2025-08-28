const mongoose = require('mongoose');

const userStatsSchema = new mongoose.Schema({
  user_id: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    unique: true 
  },
  lives: { 
    type: Number, 
    default: 0 
  },
  chips: { 
    type: Number, 
    default: 0 
  },
  cp: { 
    type: Number, 
    default: 0 
  },
  banChips: { 
    type: Number, 
    default: 0 
  },
  ad_views: { 
    type: Number, 
    default: 0 
  },
  chat_hours_today: { 
    type: Number, 
    default: 0 
  },
  monthly_appeals: { 
    type: Number, 
    default: 0 
  },
  last_online: { 
    type: Date, 
    default: Date.now 
  },
  daily_reset: { 
    type: Date, 
    default: Date.now 
  },
  monthly_reset: { 
    type: Date, 
    default: Date.now 
  },
  missed_calls: { 
    type: Number, 
    default: 0 
  },
  refused_calls: { 
    type: Number, 
    default: 0 
  },
  total_online_time: { 
    type: Number, 
    default: 0 
  },
  lastActivityCheck: { 
    type: Date, 
    default: Date.now 
  },
  reservedCp: { 
    type: Number, 
    default: 0 
  }
});

module.exports = mongoose.model('UserStats', userStatsSchema);