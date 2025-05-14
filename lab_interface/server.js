/**
 * HTTP Request Smuggling Lab Interface Server
 * 
 * Этот файл реализует серверную часть интерактивного веб-интерфейса
 * для лаборатории по изучению HTTP Request Smuggling уязвимостей.
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const winston = require('winston');
const fs = require('fs');
const { Client } = require('@elastic/elasticsearch');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

// Инициализация Express
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Настройки среды
const PORT = process.env.PORT || 8081;
const ELASTICSEARCH_HOST = process.env.ELASTIC_HOST || 'http://elasticsearch:9200';
const BACKEND_HOST = process.env.BACKEND_HOST || 'http://backend:3000';
const FRONTEND_HOST = process.env.FRONTEND_HOST || 'http://frontend:80';

// Настройка логирования
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir);
}

const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: 'lab-interface' },
    transports: [
        new winston.transports.File({ 
            filename: path.join(logDir, 'error.log'), 
            level: 'error' 
        }),
        new winston.transports.File({ 
            filename: path.join(logDir, 'combined.log') 
        }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Инициализация Elasticsearch клиента
const esClient = new Client({
    node: ELASTICSEARCH_HOST
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// Настройка сессий - используем для идентификации пользователей
app.use(session({
    secret: 'http-smuggling-lab-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, // в лабораторной среде можно использовать без HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 часа
    },
    genid: (req) => {
        // Генерируем уникальный ID для сессии
        return uuidv4();
    }
}));

// Middleware для логирования каждого запроса с ID сессии
app.use((req, res, next) => {
    const sessionId = req.session.id;
    const username = req.session.username || 'anonymous';
    
    // Добавляем информацию о сессии в логи
    logger.info(`Request: ${req.method} ${req.originalUrl}`, {
        sessionId,
        username,
        ip: req.ip
    });
    
    // Продолжаем обработку запроса
    next();
});

// Настраиваем статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Маршруты API

// Установка имени пользователя для текущей сессии
app.post('/api/session/username', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }
    
    // Сохраняем имя пользователя в сессии
    req.session.username = username;
    
    logger.info(`Username set for session`, {
        sessionId: req.session.id,
        username
    });
    
    res.json({ success: true, username, sessionId: req.session.id });
});

// Получение текущей сессии
app.get('/api/session', (req, res) => {
    const username = req.session.username || null;
    const sessionId = req.session.id;
    
    res.json({ username, sessionId });
});

// Поиск логов в Elasticsearch
app.get('/api/logs', async (req, res) => {
    try {
        const { sessionId, limit = 50, from = 0 } = req.query;
        
        // Создаём базовый запрос
        const baseQuery = {
            bool: {
                must: []
            }
        };
        
        // Если указан sessionId, добавляем его в условия поиска
        if (sessionId) {
            baseQuery.bool.must.push({
                match: {
                    "sessionId.keyword": sessionId
                }
            });
        }
        
        // Выполняем поисковый запрос в Elasticsearch
        const { body } = await esClient.search({
            index: 'http_smuggling_lab-*',
            body: {
                size: limit,
                from: from,
                sort: [
                    { "@timestamp": { order: "desc" } }
                ],
                query: baseQuery
            }
        });
        
        // Преобразуем результаты в удобный формат
        const logs = body.hits.hits.map(hit => {
            return {
                id: hit._id,
                timestamp: hit._source['@timestamp'],
                server: hit._source.server,
                method: hit._source.request_method,
                uri: hit._source.request_uri,
                status: hit._source.status,
                contentLength: hit._source.content_length,
                transferEncoding: hit._source.transfer_encoding,
                smugglingIndicator: hit._source.smuggling_indicator,
                sessionId: hit._source.sessionId,
                username: hit._source.username
            };
        });
        
        res.json({ logs, total: body.hits.total.value });
    } catch (error) {
        logger.error('Error searching logs', { error: error.toString() });
        res.status(500).json({ error: 'Failed to search logs', details: error.toString() });
    }
});

// Отправка HTTP-запроса к frontend серверу
app.post('/api/send-request', async (req, res) => {
    try {
        const { request, attackType } = req.body;
        const sessionId = req.session.id;
        const username = req.session.username || 'anonymous';
        
        if (!request) {
            return res.status(400).json({ error: 'Request content is required' });
        }
        
        // Логируем запрос
        logger.info('Sending custom request', {
            sessionId,
            username,
            attackType,
            requestContent: request
        });
        
        // Отправляем запрос к frontend серверу
        // Здесь нужно реализовать отправку HTTP-запроса с сохранением всех заголовков
        // В рамках лаборатории, это может потребовать дополнительной реализации
        
        // Временная имитация ответа
        const response = {
            status: 200,
            statusText: 'OK',
            headers: {
                'content-type': 'text/plain',
                'content-length': '25'
            },
            body: 'Request processed successfully'
        };
        
        res.json({
            success: true,
            response,
            sessionInfo: { sessionId, username }
        });
    } catch (error) {
        logger.error('Error sending request', { error: error.toString() });
        res.status(500).json({ error: 'Failed to send request', details: error.toString() });
    }
});

// Получение информации о логах атак
app.get('/api/attack-logs', async (req, res) => {
    try {
        // Запрос к Elasticsearch для получения информации о потенциальных атаках
        const { body } = await esClient.search({
            index: 'http_smuggling_lab-*',
            body: {
                size: 0,
                query: {
                    bool: {
                        should: [
                            { exists: { field: "smuggling_indicator" } },
                            { term: { "request_uri.keyword": "/admin" } },
                            { term: { "status": 403 } }
                        ],
                        minimum_should_match: 1
                    }
                },
                aggs: {
                    by_session: {
                        terms: {
                            field: "sessionId.keyword",
                            size: 100
                        },
                        aggs: {
                            by_username: {
                                terms: {
                                    field: "username.keyword",
                                    size: 1
                                }
                            },
                            by_indicator: {
                                terms: {
                                    field: "smuggling_indicator.keyword",
                                    size: 10
                                }
                            },
                            by_status: {
                                terms: {
                                    field: "status",
                                    size: 10
                                }
                            },
                            latest: {
                                top_hits: {
                                    size: 1,
                                    sort: [
                                        { "@timestamp": { order: "desc" } }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        });
        
        // Обрабатываем результаты агрегации
        const sessions = body.aggregations.by_session.buckets.map(session => {
            const latestHit = session.latest.hits.hits[0]._source;
            
            return {
                sessionId: session.key,
                username: session.by_username.buckets.length > 0 
                    ? session.by_username.buckets[0].key 
                    : 'anonymous',
                count: session.doc_count,
                indicators: session.by_indicator.buckets.map(b => ({
                    name: b.key,
                    count: b.doc_count
                })),
                statuses: session.by_status.buckets.map(b => ({
                    code: b.key,
                    count: b.doc_count
                })),
                lastSeen: latestHit['@timestamp']
            };
        });
        
        res.json({ sessions });
    } catch (error) {
        logger.error('Error getting attack logs', { error: error.toString() });
        res.status(500).json({ error: 'Failed to get attack logs', details: error.toString() });
    }
});

// WebSocket для обновления информации о логах в реальном времени
io.on('connection', (socket) => {
    logger.info('New WebSocket connection', {
        socketId: socket.id
    });
    
    // Привязка сокета к ID сессии
    socket.on('register', (data) => {
        const { sessionId, username } = data;
        
        if (sessionId) {
            socket.sessionId = sessionId;
            socket.username = username || 'anonymous';
            
            logger.info('Socket registered with session', {
                socketId: socket.id,
                sessionId,
                username: socket.username
            });
            
            // Отправляем подтверждение
            socket.emit('registered', { sessionId, username: socket.username });
        }
    });
    
    // Отключение сокета
    socket.on('disconnect', () => {
        logger.info('WebSocket disconnected', {
            socketId: socket.id,
            sessionId: socket.sessionId
        });
    });
});

// Периодический опрос Elasticsearch для обновления логов
const POLL_INTERVAL = 5000; // 5 секунд
setInterval(async () => {
    try {
        const { body } = await esClient.search({
            index: 'http_smuggling_lab-*',
            body: {
                size: 10,
                sort: [
                    { "@timestamp": { order: "desc" } }
                ],
                query: {
                    range: {
                        "@timestamp": {
                            gte: "now-5s"
                        }
                    }
                }
            }
        });
        
        if (body.hits.hits.length > 0) {
            // Преобразуем результаты в удобный формат
            const logs = body.hits.hits.map(hit => {
                return {
                    id: hit._id,
                    timestamp: hit._source['@timestamp'],
                    server: hit._source.server,
                    method: hit._source.request_method,
                    uri: hit._source.request_uri,
                    status: hit._source.status,
                    contentLength: hit._source.content_length,
                    transferEncoding: hit._source.transfer_encoding,
                    smugglingIndicator: hit._source.smuggling_indicator,
                    sessionId: hit._source.sessionId,
                    username: hit._source.username
                };
            });
            
            // Отправляем обновления клиентам
            io.emit('logs-update', { logs });
        }
    } catch (error) {
        logger.error('Error polling logs', { error: error.toString() });
    }
}, POLL_INTERVAL);

// Маршрут для основной страницы
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
server.listen(PORT, () => {
    logger.info(`HTTP Request Smuggling Lab Interface running on port ${PORT}`);
});