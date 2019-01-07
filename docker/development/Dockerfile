# based on latest vswitch image
FROM contivvpp/vswitch

# replaces contiv-agent binary with locally built one
COPY contiv-agent /usr/bin/contiv-agent

# temporary
COPY contiv-init /usr/bin/contiv-init
COPY supervisord.conf /etc/supervisord.conf
