// Minimal serverless function for Vercel
module.exports = (req, res) => {
  res.status(200).json({
    message: 'Hello from A Final Message!',
    method: req.method,
    url: req.url,
    timestamp: new Date().toISOString()
  });
};