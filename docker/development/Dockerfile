# based on latest vswitch image
FROM contivvpp/vswitch

# replaces contiv-agent binary with locally built one
COPY cmd/contiv-agent/contiv-agent /usr/bin/contiv-agent

# temporary
COPY cmd/contiv-init/contiv-init /usr/bin/contiv-init
COPY docker/ubuntu-based/prod/vswitch/supervisord.conf /etc/supervisord.conf