const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true 
  },
  password: { 
    type: String, 
    required: true 
  },
  birthdate: { 
    type: Date, 
    required: true 
  },
  gender: { 
    type: String, 
    enum: ['male', 'female'], 
    required: true 
  },
  preferredGender: { 
    type: String, 
    enum: ['male', 'female', 'any'], 
    required: true 
  },
  preferredAgeMin: { 
    type: Number, 
    required: true 
  },
  preferredAgeMax: { 
    type: Number, 
    required: true 
  },
  style: { 
    type: String, 
    default: 'cosmic' 
  },
  referral_code: { 
    type: String, 
    unique: true 
  },
  referred_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  subscriptionExpiresAt: { 
    type: Date, 
    required: true 
  },
  verificationToken: { 
    type: String 
  },
  emailVerified: { 
    type: Boolean, 
    default: false 
  },
  rulesAgreed: { 
    type: Boolean, 
    default: false 
  },
  status: { 
    type: String, 
    enum: ['online', 'busy'], 
    default: 'busy' 
  },
  isPaid: { 
    type: Boolean, 
    default: false 
  },
  fullAccessActivated: { 
    type: Boolean, 
    default: false 
  },
  settings: {
    notifications: { 
      type: Boolean, 
      default: true 
    },
    language: { 
      type: String, 
      default: 'ru' 
    },
    theme: { 
      type: String, 
      default: 'light' 
    }
  },
    notifiedExpired: {
      type: Boolean,
      default: false
  },
  autoGeneratePosts: {
    type: Boolean,
    default: false
  },
  isAdmin: { 
    type: Boolean, 
    default: false 
  }
});
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
module.exports = mongoose.model('User', userSchema);