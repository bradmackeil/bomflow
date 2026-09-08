exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, body: 'Bad Request' };
  }

  const { token, path } = body;

  if (!token || !path) {
    return { statusCode: 400, body: JSON.stringify({ status: 'error', message: 'Missing token or path' }) };
  }

  // Restrict to item endpoints only
  if (!/^item(\/\d+(\/bom)?)?(\?.*)?$/.test(path)) {
    return { statusCode: 400, body: JSON.stringify({ status: 'error', message: 'Invalid path' }) };
  }

  let result;
  try {
    const resp = await fetch(`https://api.sosinventory.com/api/v2/${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Host: 'api.sosinventory.com',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    result = await resp.json();
    return {
      statusCode: resp.status,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify(result),
    };
  } catch (err) {
    return {
      statusCode: 502,
      body: JSON.stringify({ status: 'error', message: err.message }),
    };
  }
};
