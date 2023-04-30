const router = require('express').Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');

function requireLogin(req, res, next) {
  if (req.session.currentUser) {
    next();
  } else {
    res.redirect('/login');
  }
}

router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (username === '' || email === '' || password === '') {
    res.render('auth/signup', { errorMessage: 'Fill in all the fields' });
    return;
  }

  const user = await User.findOne({ username });
  if (user !== null) {
    res.render('auth/signup', { errorMessage: 'Username already exists' });
    return;
  }

  const saltRounds = 10;
  const salt = bcrypt.genSaltSync(saltRounds);
  const hashedPassword = bcrypt.hashSync(password, salt);

  await User.create({
    username,
    email,
    password: hashedPassword
  });
  res.redirect('/');
});

router.get('/login', (req, res) => {
  res.render('auth/login');
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === '' || password === '') {
    res.render('auth/login', { errorMessage: 'Invalid Login' });
    return;
  }

  const user = await User.findOne({ username });
  if (!user) {
    res.render('auth/login', { errorMessage: 'Invalid Login' });
    return;
  }

  if (bcrypt.compareSync(password, user.password)) {
    req.session.currentUser = user;
    res.redirect('/');
  } else {
    res.render('auth/login', { errorMessage: 'Invalid Login' });
    return;
  }
});

router.get('/main', requireLogin, (req, res) => {
  res.render('auth/main');
});

router.get('/private', requireLogin, (req, res) => {
  res.render('auth/private');
});

module.exports = router;
