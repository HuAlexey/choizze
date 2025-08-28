const mongoose = require('mongoose');

const quizSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    default: null 
  },
  quizType: { 
    type: String, 
    required: true 
  },
  cpEarned: { 
    type: Number, 
    default: 0 
  },
  completedAt: { 
    type: Date, 
    default: Date.now 
  },
  type: { 
    type: String, 
    required: true 
  },
  content: { 
    type: String, 
    required: true 
  },
  correct_answer: { 
    type: String, 
    required: true 
  },
  status: { 
    type: String, 
    default: 'active',
    enum: ['active', 'completed'] 
  }
});

module.exports = mongoose.model('Quiz', quizSchema);