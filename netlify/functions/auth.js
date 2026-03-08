const crypto = require('crypto');

exports.handler = async function(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: 'Bad Request' };
  }

  const { password } = body;
  const correctPassword = process.env.BF_PASSWORD;
  const secret = process.env.BF_SECRET;

  if (!correctPassword || !secret) {
    return { statusCode: 500, body: 'Server misconfigured' };
  }

  if (password !== correctPassword) {
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Incorrect password' })
    };
  }

  // Generate a simple HMAC token
  const expires = Date.now() + 1000 * 60 * 60 * 24 * 7; // 7 days
  const payload = `${expires}`;
  const token = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex') + '.' + expires;

  return {
    statusCode: 200,
    body: JSON.stringify({ token })
  };
};
