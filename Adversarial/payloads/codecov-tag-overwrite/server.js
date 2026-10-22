const express = require('express');

const app = express();
const port = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.json({
    message: 'demo-app',
    version: process.env.APP_VERSION || '1.0.0',
  });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('ok');
});

app.get('/codecov-marker', (req, res) => {
  res.status(200).send(`CODECOV-TAG-OVERWRITE:${process.env.CODECOV_NONCE || ''}`);
});

app.listen(port, () => {
  console.log(`demo-app listening on port ${port}`);
});
