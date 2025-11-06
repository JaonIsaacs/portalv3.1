const http = require('http');

function getCsrf() {
  return new Promise((resolve, reject) => {
    const opts = { hostname: 'localhost', port: 4000, path: '/csrf-token', method: 'GET' };
    const req = http.request(opts, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => raw += chunk);
      res.on('end', () => {
        try {
          const body = JSON.parse(raw);
          const cookies = res.headers['set-cookie'] || [];
          resolve({ csrf: body.csrfToken, cookies });
        } catch (err) { reject(err); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}
/// use the csrf token and cookies to register
function postRegister(csrf, cookies) {
  return new Promise((resolve, reject) => {
    ///name may need to be changed 
    const data = JSON.stringify({ email: 'user@example.com', password: 'Password123!', name: 'Tester' });
    const opts = {
      hostname: 'localhost', port: 4000, path: '/api/auth/register', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'csrf-token': csrf,
        'Cookie': cookies.join('; ')
      }
    };

    const req = http.request(opts, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => raw += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: raw }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}
// run the test
(async () => {
  try {
    const { csrf, cookies } = await getCsrf();
    console.log('CSRF token:', csrf);
    console.log('Cookies:', cookies);
    const resp = await postRegister(csrf, cookies.map(c => c.split(';')[0]));
    console.log('Status:', resp.status);
    console.log('Body:', resp.body);
  } catch (err) {
    console.error('Error:', err.message);
    console.error(err);
  }
})();
