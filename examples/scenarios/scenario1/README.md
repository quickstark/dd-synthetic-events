# Scenario 1: NetBotz Communication Lost

This scenario simulates a critical alert from a NetBotz environmental monitoring device that has lost communication.

## Files

- `api_events.json`: Events for direct submission to Datadog API
- `email_events.json`: Email templates for email-based alerts

## Description

The alerts represent a critical situation where a NetBotz environmental monitor in the TMA Washington DC 11th Floor IDF has lost connection. This scenario demonstrates how the same event can be submitted both directly via the Datadog API and through an email-based alert system.

## Usage

### Run the complete scenario:

```bash
# Set required API keys
export DD_API_KEY=your_datadog_api_key
export SENDGRID_API_KEY=your_sendgrid_api_key

# Run both API and email events
./run.sh scenario --scenario-dir examples/scenarios/scenario1
```

### Or run parts of the scenario individually:

#### Send API events only:

```bash
export DD_API_KEY=your_datadog_api_key
./run.sh file examples/scenarios/scenario1/api_events.json
```

#### Send email alerts only:

```bash
export SENDGRID_API_KEY=your_sendgrid_api_key
./run.sh email --template examples/scenarios/scenario1/email_events.json
```

### Notes

- Both events include the same alert information but are delivered through different channels
- The email contains all the details of the alert but doesn't include Datadog-specific fields like aggregation_key
- The API event includes an aggregation_key ("netbotz_nbErrorCond_B947EC0F") that could be used to correlate with other events