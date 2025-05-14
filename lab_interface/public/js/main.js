/**
 * HTTP Request Smuggling Lab Interface - Main JavaScript
 */

(function() {
    // Инициализация WebSocket соединения
    const socket = io();

    // Текущий контекст состояния
    const state = {
        sessionId: null,
        username: null,
        currentAttackType: 'cl-te',
        currentStep: 0,
        simulationActive: false,
        logs: []
    };

    // Описания типов атак, шаблоны и шаги уже были определены ранее...

    // DOM элементы
    document.addEventListener('DOMContentLoaded', function() {
        // Получаем ссылки на DOM элементы
        
        // User panel elements
        const userInfo = document.getElementById('user-info');
        const userLogin = document.getElementById('user-login');
        const usernameInput = document.getElementById('username-input');
        const saveUsernameBtn = document.getElementById('save-username');
        const usernameDisplay = document.getElementById('username-display');
        const sessionIdDisplay = document.getElementById('session-id-display');
        
        // Attack type elements
        const attackTypeSelect = document.getElementById('attack-type');
        const attackDescription = document.getElementById('attack-description');
        
        // Request editor elements
        const normalRequest = document.getElementById('normal-request');
        const exploitRequest = document.getElementById('exploit-request');
        const customRequest = document.getElementById('custom-request');
        
        // Tabs
        const tabButtons = document.querySelectorAll('.tab');
        const tabContents = document.querySelectorAll('.tab-content');
        
        // Buttons
        const btnValidate = document.getElementById('btn-validate');
        const btnSend = document.getElementById('btn-send');
        const btnReset = document.getElementById('btn-reset');
        const btnStep = document.getElementById('btn-step');
        
        // Containers and visualization elements
        const logContainer = document.getElementById('log-container');
        const realtimeLogs = document.getElementById('realtime-logs');
        const progressBar = document.getElementById('progress-bar');
        const explanationContainer = document.getElementById('explanation-container');
        const packetContainer = document.getElementById('packet-container');
        const rawRequest = document.getElementById('raw-request');
        const frontendInterpretation = document.getElementById('frontend-interpretation');
        const backendInterpretation = document.getElementById('backend-interpretation');
        
        // Session and logs elements
        const sessionFilter = document.getElementById('session-filter');
        const attackLogsContent = document.getElementById('attack-logs-content');
        const sessionStatsContent = document.getElementById('session-stats-content');
        
        // Инициализация приложения
        initApp();
        
        // Назначаем обработчики событий
        
        // Сохранение имени пользователя
        saveUsernameBtn.addEventListener('click', function() {
            saveUsername();
        });
        
        // Изменение типа атаки
        attackTypeSelect.addEventListener('change', function() {
            state.currentAttackType = this.value;
            updateAttackDescription();
            updateRequestTemplates();
            resetSimulation();
            updateVisualization();
        });
        
        // Обработчики табов
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                const tabId = this.getAttribute('data-tab');
                activateTab(tabId);
            });
        });
        
        // Фильтр сессий для логов
        sessionFilter.addEventListener('change', function() {
            loadLogs();
        });
        
        // Валидация пользовательского запроса
        btnValidate.addEventListener('click', function() {
            validateCustomRequest();
        });
        
        // Отправка запроса
        btnSend.addEventListener('click', function() {
            if (state.simulationActive) return;
            
            const activeTabId = document.querySelector('.tab.active').getAttribute('data-tab');
            let requestContent = '';
            
            // Выбираем контент запроса в зависимости от активного таба
            switch (activeTabId) {
                case 'tab-normal':
                    requestContent = normalRequest.value;
                    break;
                case 'tab-exploit':
                    requestContent = exploitRequest.value;
                    break;
                case 'tab-custom':
                    requestContent = customRequest.value;
                    break;
            }
            
            // Начинаем симуляцию
            startSimulation();
            
            // Отправляем запрос на сервер
            sendRequest(requestContent);
        });
        
        // Сброс симуляции
        btnReset.addEventListener('click', function() {
            resetSimulation();
        });
        
        // Выполнение следующего шага симуляции
        btnStep.addEventListener('click', function() {
            nextStep();
        });
        
        // WebSocket обработчики
        
        // Соединение установлено
        socket.on('connect', function() {
            console.log('WebSocket соединение установлено');
            
            // Регистрируем сессию, если уже авторизованы
            if (state.sessionId && state.username) {
                socket.emit('register', {
                    sessionId: state.sessionId,
                    username: state.username
                });
            }
        });
        
        // Сессия зарегистрирована
        socket.on('registered', function(data) {
            console.log('Сессия зарегистрирована:', data);
        });
        
        // Получены новые логи
        socket.on('logs-update', function(data) {
            if (data.logs && data.logs.length > 0) {
                // Добавляем новые логи в локальное состояние
                state.logs = [...data.logs, ...state.logs].slice(0, 100);
                
                // Обновляем отображение логов, если открыт соответствующий таб
                if (document.getElementById('tab-all-logs').classList.contains('active')) {
                    updateRealtimeLogs();
                }
            }
        });
        
        // Функции приложения
        
        // Инициализация приложения
        function initApp() {
            // Получаем информацию о сессии
            fetchSessionInfo();
            
            // Загружаем логи
            loadLogs();
            
            // Устанавливаем описание выбранного типа атаки
            updateAttackDescription();
            
            // Устанавливаем шаблоны запросов
            updateRequestTemplates();
            
            // Сбрасываем симуляцию
            resetSimulation();
        }
        
        // Получение информации о сессии
        async function fetchSessionInfo() {
            try {
                const response = await fetch('/api/session');
                const data = await response.json();
                
                if (data.sessionId) {
                    state.sessionId = data.sessionId;
                    sessionIdDisplay.textContent = data.sessionId;
                    
                    if (data.username) {
                        state.username = data.username;
                        usernameDisplay.textContent = data.username;
                        userInfo.style.display = 'block';
                        userLogin.style.display = 'none';
                        
                        // Регистрируем сессию в WebSocket
                        socket.emit('register', {
                            sessionId: state.sessionId,
                            username: state.username
                        });
                    }
                }
            } catch (error) {
                console.error('Ошибка при получении информации о сессии:', error);
            }
        }
        
        // Сохранение имени пользователя
        async function saveUsername() {
            const username = usernameInput.value.trim();
            
            if (!username) {
                alert('Пожалуйста, введите имя пользователя');
                return;
            }
            
            try {
                const response = await fetch('/api/session/username', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    state.username = data.username;
                    state.sessionId = data.sessionId;
                    
                    usernameDisplay.textContent = data.username;
                    sessionIdDisplay.textContent = data.sessionId;
                    
                    userInfo.style.display = 'block';
                    userLogin.style.display = 'none';
                    
                    // Регистрируем сессию в WebSocket
                    socket.emit('register', {
                        sessionId: state.sessionId,
                        username: state.username
                    });
                    
                    // Обновляем логи
                    loadLogs();
                }
            } catch (error) {
                console.error('Ошибка при сохранении имени пользователя:', error);
                alert('Произошла ошибка при сохранении имени пользователя');
            }
        }
        
        // Загрузка логов
        async function loadLogs() {
            try {
                // Создаем параметры запроса
                let url = '/api/logs';
                const params = new URLSearchParams();
                
                // Если выбрана фильтрация по текущей сессии
                if (sessionFilter.value === 'current' && state.sessionId) {
                    params.append('sessionId', state.sessionId);
                }
                
                params.append('limit', '50');
                
                // Выполняем запрос
                const response = await fetch(`${url}?${params.toString()}`);
                const data = await response.json();
                
                // Обновляем локальное состояние
                state.logs = data.logs || [];
                
                // Обновляем отображение
                updateRealtimeLogs();
            } catch (error) {
                console.error('Ошибка при загрузке логов:', error);
                realtimeLogs.innerHTML = '<p class="log-line error">Ошибка при загрузке логов</p>';
            }
        }
        
        // Загрузка логов атак
        async function loadAttackLogs() {
            try {
                const response = await fetch('/api/attack-logs');
                const data = await response.json();
                
                if (data.sessions && data.sessions.length > 0) {
                    let html = '';
                    
                    data.sessions.forEach(session => {
                        const indicators = session.indicators.map(ind => 
                            `<span class="indicator-tag">${ind.name}</span>`
                        ).join(' ');
                        
                        const statuses = session.statuses.map(status => 
                            `<span class="indicator-tag ${status.code >= 400 ? 'error' : ''}">${status.code}</span>`
                        ).join(' ');
                        
                        html += `
                            <div class="attack-log-row ${session.sessionId === state.sessionId ? 'highlight' : ''}">
                                <div>${session.username}</div>
                                <div>${indicators || 'Нет индикаторов'}</div>
                                <div>${statuses || 'Нет статусов'}</div>
                                <div>${new Date(session.lastSeen).toLocaleString()}</div>
                            </div>
                        `;
                    });
                    
                    attackLogsContent.innerHTML = html;
                } else {
                    attackLogsContent.innerHTML = '<p class="log-line">Нет данных об атаках</p>';
                }
            } catch (error) {
                console.error('Ошибка при загрузке логов атак:', error);
                attackLogsContent.innerHTML = '<p class="log-line error">Ошибка при загрузке логов атак</p>';
            }
        }
        
        // Загрузка статистики сессий
        async function loadSessionStats() {
            try {
                const response = await fetch('/api/logs');
                const data = await response.json();
                
                if (data.logs && data.logs.length > 0) {
                    // Группируем логи по сессиям
                    const sessionMap = {};
                    
                    data.logs.forEach(log => {
                        if (!log.sessionId) return;
                        
                        if (!sessionMap[log.sessionId]) {
                            sessionMap[log.sessionId] = {
                                username: log.username || 'anonymous',
                                count: 0,
                                lastSeen: log.timestamp
                            };
                        }
                        
                        sessionMap[log.sessionId].count++;
                        
                        // Обновляем время последней активности
                        if (new Date(log.timestamp) > new Date(sessionMap[log.sessionId].lastSeen)) {
                            sessionMap[log.sessionId].lastSeen = log.timestamp;
                        }
                    });
                    
                    // Формируем HTML
                    let html = `
                        <div class="session-stats-row session-stats-header">
                            <div>Пользователь</div>
                            <div>Количество логов</div>
                            <div>Последняя активность</div>
                        </div>
                    `;
                    
                    Object.keys(sessionMap).forEach(sessionId => {
                        const session = sessionMap[sessionId];
                        
                        html += `
                            <div class="session-stats-row ${sessionId === state.sessionId ? 'highlight' : ''}">
                                <div>${session.username} ${sessionId === state.sessionId ? '(вы)' : ''}</div>
                                <div>${session.count}</div>
                                <div>${new Date(session.lastSeen).toLocaleString()}</div>
                            </div>
                        `;
                    });
                    
                    sessionStatsContent.innerHTML = html;
                } else {
                    sessionStatsContent.innerHTML = '<p>Нет данных о сессиях</p>';
                }
            } catch (error) {
                console.error('Ошибка при загрузке статистики сессий:', error);
                sessionStatsContent.innerHTML = '<p class="log-line error">Ошибка при загрузке статистики сессий</p>';
            }
        }
        
        // Обновление отображения логов
        function updateRealtimeLogs() {
            if (state.logs.length === 0) {
                realtimeLogs.innerHTML = '<p class="log-line">Нет доступных логов</p>';
                return;
            }
            
            let html = '';
            
            state.logs.forEach(log => {
                const timestamp = new Date(log.timestamp).toLocaleString();
                const username = log.username || 'anonymous';
                const isCurrentUser = log.sessionId === state.sessionId;
                
                html += `
                    <p class="log-line ${isCurrentUser ? 'highlight' : ''}">
                        [${timestamp}] ${username}: ${log.server} ${log.method} ${log.uri} - ${log.status}
                        ${log.smugglingIndicator ? `<span class="warning">[${log.smugglingIndicator}]</span>` : ''}
                    </p>
                `;
            });
            
            realtimeLogs.innerHTML = html;
        }
        
        // Активация вкладки
        function activateTab(tabId) {
            // Деактивируем все вкладки
            tabButtons.forEach(tab => {
                tab.classList.remove('active');
            });
            
            tabContents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Активируем выбранную вкладку
            document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
            document.getElementById(tabId).classList.add('active');
            
            // Если открыта вкладка с логами атак, обновляем данные
            if (tabId === 'tab-attack-logs') {
                loadAttackLogs();
            }
            
            // Если открыта вкладка со статистикой сессий, обновляем данные
            if (tabId === 'tab-session-logs') {
                loadSessionStats();
            }
        }
        
        // Обновление описания атаки
        function updateAttackDescription() {
            attackDescription.textContent = attackDescriptions[state.currentAttackType];
            
            // Обновляем полное объяснение атаки
            explanationContainer.innerHTML = fullExplanations[state.currentAttackType];
        }
        
        // Обновление шаблонов запросов
        function updateRequestTemplates() {
            normalRequest.value = requestTemplates[state.currentAttackType].normal;
            exploitRequest.value = requestTemplates[state.currentAttackType].exploit;
            customRequest.value = requestTemplates[state.currentAttackType].exploit;
        }
        
        // Валидация пользовательского запроса
        function validateCustomRequest() {
            const requestContent = customRequest.value.trim();
            
            if (!requestContent) {
                addLog('Ошибка: Запрос пуст');
                return;
            }
            
            // Базовая валидация
            if (!requestContent.includes('HTTP/1.1')) {
                addLog('Предупреждение: Отсутствует HTTP/1.1 в заголовке запроса');
            }
            
            if (!requestContent.includes('Host:')) {
                addLog('Предупреждение: Отсутствует заголовок Host');
            }
            
            // Проверка на потенциальные уязвимости HTTP Request Smuggling
            const hasContentLength = requestContent.includes('Content-Length:');
            const hasTransferEncoding = requestContent.includes('Transfer-Encoding:');
            
            if (hasContentLength && hasTransferEncoding) {
                addLog('Потенциальная уязвимость: Запрос содержит оба заголовка Content-Length и Transfer-Encoding');
                
                // Проверка конкретных паттернов
                if (requestContent.includes('Transfer-Encoding: chunked') && requestContent.includes('Content-Length:')) {
                    addLog('Обнаружена потенциальная уязвимость CL.TE или TE.CL');
                }
                
                if (requestContent.includes('Transfer-Encoding: chunked') && 
                    (requestContent.match(/Transfer-Encoding:/g) || []).length > 1) {
                    addLog('Обнаружена потенциальная уязвимость TE.TE (множественные заголовки Transfer-Encoding)');
                }
            }
            
            // Проверка на обфускацию
            if (requestContent.includes('Transfer-Encoding') && !requestContent.includes('Transfer-Encoding: chunked')) {
                addLog('Примечание: Обнаружено нестандартное значение Transfer-Encoding');
            }
            
            // Проверка на вложенные чанки
            if (requestContent.includes('0\r\n\r\n') || requestContent.includes('0\n\n')) {
                addLog('Примечание: Обнаружен терминатор chunked-кодирования (0 с пустой строкой)');
            }
            
            addLog('✓ Валидация запроса завершена');
        }
        
        // Добавление сообщения в лог
        function addLog(message) {
            const logLine = document.createElement('p');
            logLine.className = 'log-line';
            logLine.textContent = message;
            logContainer.appendChild(logLine);
            logContainer.scrollTop = logContainer.scrollHeight;
        }
        
        // Начало симуляции
        function startSimulation() {
            addLog('=== Начало симуляции ===');
            state.simulationActive = true;
            state.currentStep = 0;
            btnSend.disabled = true;
            btnStep.disabled = false;
            updateExplanation(0);
            progressBar.style.width = '0%';
            
            // Обновляем визуализацию
            updateVisualization();
        }
        
        // Сброс симуляции
        function resetSimulation() {
            state.simulationActive = false;
            state.currentStep = 0;
            btnSend.disabled = false;
            btnStep.disabled = false;
            progressBar.style.width = '0%';
            
            // Очищаем логи
            logContainer.innerHTML = '<p class="log-line">Система готова к обработке запросов...</p>';
            
            // Очищаем анимации
            packetContainer.innerHTML = '';
            
            // Сбрасываем объяснение
            explanationContainer.innerHTML = fullExplanations[state.currentAttackType];
            
            // Обновляем визуализацию
            updateVisualization();
        }
        
        // Следующий шаг симуляции
        function nextStep() {
            if (!state.simulationActive) return;
            
            const steps = attackSteps[state.currentAttackType];
            if (state.currentStep < steps.length) {
                addLog(steps[state.currentStep].log);
                updateExplanation(state.currentStep);
                
                // Создаем анимацию пакета
                if (state.currentStep === 1) {
                    createPacket('client-to-frontend');
                } else if (state.currentStep === 3) {
                    createPacket('frontend-to-backend');
                }
                
                const progress = ((state.currentStep + 1) / steps.length) * 100;
                progressBar.style.width = progress + '%';
                
                state.currentStep++;
                
                if (state.currentStep >= steps.length) {
                    btnStep.disabled = true;
                    setTimeout(() => {
                        addLog('=== Симуляция завершена ===');
                        btnSend.disabled = false;
                        state.simulationActive = false;
                    }, 1000);
                }
            }
        }
        
        // Обновление объяснения шага
        function updateExplanation(step) {
            const steps = attackSteps[state.currentAttackType];
            if (step < steps.length) {
                explanationContainer.innerHTML = `<p>${steps[step].explanation}</p>`;
            }
        }
        
        // Создание анимации пакета
        function createPacket(direction) {
            const packet = document.createElement('div');
            packet.className = 'packet';
            packet.textContent = 'HTTP';
            
            if (direction === 'client-to-frontend') {
                packet.style.top = '40px';
                packet.style.left = '10px';
                packet.style.animationName = 'moveRequestToFrontend';
            } else if (direction === 'frontend-to-backend') {
                packet.style.top = '40px';
                packet.style.left = '290px';
                packet.style.animationName = 'moveRequestToBackend';
            }
            
            packetContainer.appendChild(packet);
            
            // Удаляем пакет после анимации
            setTimeout(() => {
                packet.style.animationName = 'fadeOut';
                setTimeout(() => {
                    packet.remove();
                }, 1000);
            }, 3000);
        }
        
        // Обновление визуализации
        function updateVisualization() {
            // Обновляем визуализацию исходного запроса
            const requestToVisualize = exploitRequest.value;
            rawRequest.textContent = requestToVisualize;
            
            // Обновляем визуализацию интерпретации frontend/backend в зависимости от типа атаки
            let frontendHighlightPercent = 100;
            let backendHighlightPercent = 100;
            
            if (state.currentAttackType === 'cl-te') {
                // CL.TE: Frontend видит весь запрос, backend меньше из-за chunked-кодирования
                frontendHighlightPercent = 100;
                backendHighlightPercent = 75;
            } else if (state.currentAttackType === 'te-cl') {
                // TE.CL: Frontend видит весь chunked запрос, backend только до Content-Length
                frontendHighlightPercent = 100;
                backendHighlightPercent = 60;
            } else if (state.currentAttackType === 'te-te') {
                // TE.TE: Оба сервера обрабатывают по-разному из-за разных заголовков
                frontendHighlightPercent = 90;
                backendHighlightPercent = 100;
            }
            
            // Применяем визуализацию
            frontendInterpretation.innerHTML = `<div class="highlight-overlay" style="width: ${frontendHighlightPercent}%;"></div>${requestToVisualize}`;
            backendInterpretation.innerHTML = `<div class="highlight-overlay" style="width: ${backendHighlightPercent}%;"></div>${requestToVisualize}`;
        }
        
        // Отправка запроса на сервер
        async function sendRequest(requestContent) {
            try {
                const response = await fetch('/api/send-request', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        request: requestContent,
                        attackType: state.currentAttackType
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    addLog(`Запрос успешно отправлен`);
                    addLog(`Статус ответа: ${data.response.status} ${data.response.statusText}`);
                }
            } catch (error) {
                console.error('Ошибка при отправке запроса:', error);
                addLog(`Ошибка при отправке запроса: ${error.message}`);
            }
        }
    });
})();