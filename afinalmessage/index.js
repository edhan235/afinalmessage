const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

// Simple test route
app.get('/', (req, res) => {
    res.send('<h1>Hello from A Final Message!</h1><p>Server is working!</p>');
});

// Test API route
app.get('/test', (req, res) => {
    res.json({ message: 'API is working!', timestamp: new Date() });
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});