const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const morgan = require('morgan');
const winston = require('winston');
const getRawBody = require('raw-body');

// Create Express app
const app = express();
const port = 3000;

// Configure logging
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

// Create a logger for HTTP requests with detailed information
const logger = winston.createLogger({
    level: 'debug',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: 'backend-server' },
    transports: [
        new winston.transports.File({ 
            filename: path.join(logDir, 'error.log'), 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: path.join(logDir, 'combined.log') 
        }),
        new winston.transports.File({ 
            filename: path.join(logDir, 'raw_requests.log'),
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        })
    ]
});

// Add console logging for development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.combine(
            winston.format.colorize(),
            winston.format.simple()
        )
    }));
}

// Create a log stream for Morgan
const accessLogStream = fs.createWriteStream(
    path.join(logDir, 'access.log'), 
    { flags: 'a' }
);

// Setup request logging middleware
app.use(morgan('combined', { stream: accessLogStream }));

// Custom middleware to log raw request data (important for HTTP smuggling analysis)
app.use((req, res, next) => {
    // Log detailed request information
    const requestInfo = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        ip: req.ip,
        timestamp: new Date().toISOString()
    };
    
    // Get the raw request body for analysis
    getRawBody(req, {
        length: req.headers['content-length'],
        limit: '10mb',
        encoding: true
    })
    .then(rawBody => {
        // Store the raw body for later use if needed
        req.rawBody = rawBody;
        
        // Log the complete request including body
        logger.debug('Incoming request', {
            ...requestInfo,
            rawBody: rawBody
        });
        
        // Continue processing the request
        next();
    })
    .catch(err => {
        logger.error('Error parsing request body', {
            ...requestInfo,
            error: err.message
        });
        next(err);
    });
});

// Configure standard body parser after logging raw data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
    logger.info('Received GET request to root');
    res.send('HTTP Request Smuggling Lab - Backend Server');
});

app.post('/api/data', (req, res) => {
    logger.info('Received POST request to /api/data', { body: req.body });
    res.json({ message: 'Data received', data: req.body });
});

// Route specifically for testing smuggled requests
app.get('/admin', (req, res) => {
    logger.warn('Received request to admin area', {
        headers: req.headers,
        ip: req.ip
    });
    res.status(403).send('Access Forbidden');
});

// Handle errors
app.use((err, req, res, next) => {
    logger.error('Server error', { error: err.message, stack: err.stack });
    res.status(500).send('Server Error');
});

// Start server
app.listen(port, () => {
    logger.info(`Backend server running on port ${port}`);
});