const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  tokenId: { type: String, required: true, unique: true, index: true },
  tokenHash: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  revoked: { type: Boolean, default: false },
  replacedByToken: { type: String }
});

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
