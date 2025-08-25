// api/index.js - Vercel serverless function
export default function handler(req, res) {
  // Handle all routes
  const { url, method } = req;
  
  if (url === '/' || url === '/api') {
    return res.status(200).send(`
      <html>
        <head><title>A Final Message</title></head>
        <body>
          <h1>Hello from A Final Message!</h1>
          <p>Server is working!</p>
          <p>Method: ${method}</p>
          <p>Time: ${new Date().toISOString()}</p>
          <a href="/api/test">Test API</a>
        </body>
      </html>
    `);
  }
  
  if (url === '/api/test') {
    return res.status(200).json({
      message: 'API is working!',
      timestamp: new Date().toISOString(),
      method: method
    });
  }
  
  // Default response for other routes
  res.status(200).json({
    message: 'A Final Message API',
    url: url,
    method: method,
    timestamp: new Date().toISOString()
  });
}