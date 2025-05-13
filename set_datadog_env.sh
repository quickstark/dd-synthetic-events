#!/bin/bash

# Script to set Datadog environment variables

# Prompt for API key securely
echo -n "Enter your Datadog API key: "
read -s DD_API_KEY
echo ""

# Prompt for App key (optional)
echo -n "Enter your Datadog Application key (optional, press Enter to skip): "
read -s DD_APP_KEY
echo ""

# Set site if not already set
DD_SITE=${DD_SITE:-datadoghq.com}
echo "Using Datadog site: $DD_SITE"

# Set the variables in the environment
export DD_API_KEY
export DD_APP_KEY
export DD_SITE

# Mask the keys for display
if [ -n "$DD_API_KEY" ] && [ ${#DD_API_KEY} -gt 8 ]; then
    MASKED_API_KEY="${DD_API_KEY:0:4}...${DD_API_KEY: -4}"
    echo "API key set: $MASKED_API_KEY"
else
    echo "API key is too short or not set"
fi

if [ -n "$DD_APP_KEY" ] && [ ${#DD_APP_KEY} -gt 8 ]; then
    MASKED_APP_KEY="${DD_APP_KEY:0:4}...${DD_APP_KEY: -4}"
    echo "App key set: $MASKED_APP_KEY"
else
    if [ -n "$DD_APP_KEY" ]; then
        echo "App key is too short"
    else
        echo "App key not set"
    fi
fi

echo ""
echo "Environment variables set. You can now run commands like:"
echo "python src/simulator.py --debug test-logs"
echo "python src/simulator.py --debug scenario --scenario-dir examples/scenarios/scenario2" 