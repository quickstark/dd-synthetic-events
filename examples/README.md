# Datadog Synthetic Events Examples

This directory contains example event definitions and templates for the Datadog Synthetic Events tool.

## Basic Examples

- `event_template.json`: Template showing all available Datadog event fields

## Scenarios

The `scenarios` directory contains complete examples that demonstrate different use cases:

- **Scenario 1**: Cisco DNA Center Network Device Unreachable alert
  - Demonstrates submitting the same event via API and email

## Running Examples

### API Events

```bash
# Send a single event
./run.sh file examples/event_template.json

# Send a scenario's API events
./run.sh file examples/scenarios/scenario1/api_events.json
```

### Email Events

```bash
# Make sure you have a SendGrid API key
export SENDGRID_API_KEY=your_sendgrid_api_key

# Send an email alert
./run.sh email --template examples/scenarios/scenario1/email_events.json
```

## Creating Your Own Scenarios

To create a new scenario:

1. Create a new directory under `scenarios/`
2. Create `api_events.json` for direct Datadog API events
3. Create `email_events.json` for email-based alerts
4. Add a README.md describing the scenario

Follow the structure in existing scenarios as a guide.

## Tagging Best Practices

When you can't use aggregation keys (e.g., when integrating with third-party systems that don't support them), consistent tagging is your best alternative for correlation.

### Recommended Tag Patterns

- **`env:name`** - Environment (prod, staging, dev)
- **`service:name`** - Service or application name
- **`incident:id`** - Incident identifier for correlation
- **`version:number`** - Software version
- **`component:name`** - Specific component affected