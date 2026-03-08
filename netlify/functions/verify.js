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

  const { token } = body;
  const secret = process.env.BF_SECRET;

  if (!secret || !token) {
    return { statusCode: 401, body: JSON.stringify({ valid: false }) };
  }

  const [hash, expires] = token.split('.');

  if (!hash || !expires || Date.now() > parseInt(expires)) {
    return { statusCode: 401, body: JSON.stringify({ valid: false }) };
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(expires)
    .digest('hex');

  const valid = hash === expected;

  return {
    statusCode: valid ? 200 : 401,
    body: JSON.stringify({ valid })
  };
};
