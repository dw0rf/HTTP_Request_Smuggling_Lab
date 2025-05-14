#!/bin/sh

# Ждем пока Kibana запустится
echo "Waiting for Kibana to start..."
until curl -s http://kibana:5601/api/status | grep -q "available"; do
  sleep 5
done

# Импортируем визуализации
echo "Importing visualizations..."
curl -X POST http://kibana:5601/api/saved_objects/_import \
  -H "kbn-xsrf: true" \
  --form file=@/data/kibana-visualizations.json

# Импортируем дашборд
echo "Importing dashboard..."
curl -X POST http://kibana:5601/api/saved_objects/_import \
  -H "kbn-xsrf: true" \
  --form file=@/data/kibana-dashboard.json

echo "Setup complete!"