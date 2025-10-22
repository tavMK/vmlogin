const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const passport = require('passport');
const session = require('express-session');
const axios = require('axios');
require('dotenv').config();

// Passport Strategies
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const InstagramStrategy = require('passport-instagram').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(session({
  secret: process.env.SESSION_SECRET || 'session-secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// In-memory user storage (replace with database in production)
const users = [];
const socialProfiles = [];

// Passport Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id) || socialProfiles.find(u => u.id === id);
  done(null, user || null);
});

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = socialProfiles.find(u => u.providerId === profile.id && u.provider === 'google');
    
    if (!user) {
      user = {
        id: `google_${profile.id}`,
        provider: 'google',
        providerId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        picture: profile.photos[0].value,
        accessToken: accessToken
      };
      socialProfiles.push(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Instagram Strategy
passport.use(new InstagramStrategy({
  clientID: process.env.INSTAGRAM_CLIENT_ID,
  clientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
  callbackURL: "/auth/instagram/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = socialProfiles.find(u => u.providerId === profile.id && u.provider === 'instagram');
    
    if (!user) {
      user = {
        id: `instagram_${profile.id}`,
        provider: 'instagram',
        providerId: profile.id,
        username: profile.username,
        name: profile.displayName,
        accessToken: accessToken
      };
      socialProfiles.push(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Facebook Strategy
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_CLIENT_ID,
  clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
  callbackURL: "/auth/facebook/callback",
  profileFields: ['id', 'emails', 'name', 'displayName', 'photos']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = socialProfiles.find(u => u.providerId === profile.id && u.provider === 'facebook');
    
    if (!user) {
      user = {
        id: `facebook_${profile.id}`,
        provider: 'facebook',
        providerId: profile.id,
        email: profile.emails ? profile.emails[0].value : null,
        name: profile.displayName,
        picture: profile.photos ? profile.photos[0].value : null,
        accessToken: accessToken
      };
      socialProfiles.push(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = socialProfiles.find(u => u.providerId === profile.id && u.provider === 'github');
    
    if (!user) {
      user = {
        id: `github_${profile.id}`,
        provider: 'github',
        providerId: profile.id,
        username: profile.username,
        name: profile.displayName,
        picture: profile.photos[0].value,
        accessToken: accessToken
      };
      socialProfiles.push(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// LinkedIn Strategy
passport.use(new LinkedInStrategy({
  clientID: process.env.LINKEDIN_CLIENT_ID,
  clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  callbackURL: "/auth/linkedin/callback",
  scope: ['r_emailaddress', 'r_liteprofile'],
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = socialProfiles.find(u => u.providerId === profile.id && u.provider === 'linkedin');
    
    if (!user) {
      user = {
        id: `linkedin_${profile.id}`,
        provider: 'linkedin',
        providerId: profile.id,
        email: profile.emails ? profile.emails[0].value : null,
        name: `${profile.name.givenName} ${profile.name.familyName}`,
        picture: profile.photos ? profile.photos[0].value : null,
        accessToken: accessToken
      };
      socialProfiles.push(user);
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

// Routes

// Regular email/password registration
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      name,
      provider: 'email'
    };

    users.push(user);

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: user.id, email: user.email, name: user.name, provider: user.provider }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Regular email/password login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(user => user.email === email);
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { 
        id: user.id, 
        email: user.email, 
        name: user.name, 
        provider: user.provider 
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Social Authentication Routes

// Google
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user.id, email: req.user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Redirect to frontend with token
    res.redirect(`http://localhost:3000/auth/success?token=${token}&provider=google`);
  }
);

// Instagram
app.get('/auth/instagram',
  passport.authenticate('instagram')
);

app.get('/auth/instagram/callback',
  passport.authenticate('instagram', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user.id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.redirect(`http://localhost:3000/auth/success?token=${token}&provider=instagram`);
  }
);

// Facebook
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user.id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.redirect(`http://localhost:3000/auth/success?token=${token}&provider=facebook`);
  }
);

// GitHub
app.get('/auth/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user.id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.redirect(`http://localhost:3000/auth/success?token=${token}&provider=github`);
  }
);

// LinkedIn
app.get('/auth/linkedin',
  passport.authenticate('linkedin')
);

app.get('/auth/linkedin/callback',
  passport.authenticate('linkedin', { failureRedirect: '/login' }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user.id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.redirect(`http://localhost:3000/auth/success?token=${token}&provider=linkedin`);
  }
);

// Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.userId) || 
               socialProfiles.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.json({ user: sanitizeUser(user) });
});

// Connect additional social accounts (for logged-in users)
app.post('/api/connect/:provider', authenticateToken, async (req, res) => {
  // This would handle connecting additional social accounts to an existing user
  // Implementation depends on your user linking strategy
});

// Utility functions
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function sanitizeUser(user) {
  const sanitized = { ...user };
  delete sanitized.password;
  delete sanitized.accessToken;
  return sanitized;
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});