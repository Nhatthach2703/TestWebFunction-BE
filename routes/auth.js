const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const {
  register,
  login,
  profile,
  refresh,
} = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.get('/profile', auth, profile);
router.post('/refresh', refresh);

module.exports = router;
