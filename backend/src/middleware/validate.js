

const validator = require('validator');

/// Whitelist regex patterns
const patterns = {

  email: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/, /// basic email
  
  password: /^[A-Za-z0-9!@#$%^&*()_+=[\]{}|;:'",.<>/?`~\\-]{8,128}$/, 
  /// Name: letters, spaces, hyphens, apostrophes
  name: /^[A-Za-z \-']{1,100}$/,
};

function validateRegistration(req, res, next) {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing fields' });

  if (!patterns.email.test(email) || !validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  if (!patterns.password.test(password)) {
    return res.status(400).json({ error: 'Invalid password format' });
  }
  if (!patterns.name.test(name)) {
    return res.status(400).json({ error: 'Invalid name' });
  }

  
  req.body.email = validator.normalizeEmail(email);
  req.body.name = validator.escape(name);

  next();
}
/// Login validation
function validateLogin(req, res, next) {
  console.log('validateLogin body:', req.body);
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (!patterns.email.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (!patterns.password.test(password)) return res.status(400).json({ error: 'Invalid password format' });
  req.body.email = validator.normalizeEmail(email);
  next();
}

module.exports = { validateRegistration, validateLogin };
