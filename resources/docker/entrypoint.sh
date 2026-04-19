#!/usr/bin/env sh
# shellcheck shell=dash

# If the configuration file exists, start the server.
exec /usr/local/bin/stalwart --config /opt/stalwart/etc/config.json
