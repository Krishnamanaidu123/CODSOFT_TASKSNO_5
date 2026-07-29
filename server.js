const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');

require('./db'); // initializes schema on first run

const authRoutes = require('./routes/auth.routes');
const fileRoutes = require('./routes/files.routes');
const adminRoutes = require('./routes/admin.routes');
const shareRoutes = require('./routes/share.routes');

const app = express();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));

// General API rate limit (in addition to the stricter ones on auth/share).
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use('/auth', authRoutes);
app.use('/files', fileRoutes);
app.use('/admin', adminRoutes);
app.use('/share', shareRoutes);

// Central error handler — catches multer errors (e.g. file too large) and
// anything else that bubbles up, without leaking stack traces to clients.
app.use((err, req, res, next) => {
  if (err && err.name === 'MulterError') {
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(config.port, () => {
  console.log(`Secure file-share server listening on port ${config.port} (${config.nodeEnv})`);
});
