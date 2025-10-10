const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

userSchema.methods.verifyPassword = function (password) {
  return bcrypt.compare(password, this.passwordHash);
};

userSchema.statics.hashPassword = function (password) {
  return bcrypt.hash(password, SALT_ROUNDS);
};

module.exports = mongoose.model('User', userSchema);
