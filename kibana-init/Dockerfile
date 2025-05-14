FROM curlimages/curl:latest

COPY kibana-dashboard.json /data/
COPY kibana-visualizations.json /data/
COPY setup-kibana.sh /

CMD ["/bin/sh", "/setup-kibana.sh"]