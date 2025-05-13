# Datadog Synthetic Events

A tool for simulating events in Datadog for testing and demonstration purposes.

## Requirements

- Docker
- Datadog API key (and optionally App key)

## Quick Start

1. Build the Docker image:

```bash
docker build -t datadog-events .
```

2. Run with your Datadog API key:

```bash
docker run -e DD_API_KEY=your_api_key_here datadog-events test
```

If you don't provide an API key, you'll be prompted to enter one interactively when using in interactive mode (`-it`).

## Environment Variables

The Docker image has placeholders for these environment variables:

- `DD_API_KEY` (required): Your Datadog API key
- `DD_APP_KEY` (optional): Your Datadog Application key
- `DD_SITE` (optional): Your Datadog site (defaults to "api.datadoghq.com")
  - Standard value for most users: "api.datadoghq.com"
  - EU customers: "api.datadoghq.eu"
  - Gov cloud: "api.ddog-gov.com"
- `SENDGRID_API_KEY` (required for email features): Your SendGrid API key
- `DD_EMAIL_ADDRESS` (optional): Datadog email address for email-to-event conversion (defaults to "event-8l2d0xg2@dtdg.co")

You should provide these values when running the container with `-e`:

```bash
docker run -e DD_API_KEY=your_api_key_here -e DD_SITE=api.datadoghq.eu datadog-events test
```

## Command Line Interface

```
Commands:
  create         Create and send a custom event (interactive)
  file           Send events from a JSON file
  stdin          Read events from stdin (JSON format)
  test           Send a single test event to Datadog
  email          Send simulated email alerts (requires SendGrid API key)
  scenario       Run a complete scenario (both API and email events)
                Flags:
                --logs-only: Process only logs (skip API and email events)
                --skip-api-events: Skip processing API events
                --skip-email-events: Skip processing email events
  send_email_file Send a saved email file directly to Datadog

Options:
  --interval FLOAT      Interval between events in seconds
  --api-key TEXT        Datadog API key (can also use DD_API_KEY env var)
  --app-key TEXT        Datadog application key (can also use DD_APP_KEY env var)
  --site TEXT           Datadog site (can also use DD_SITE env var)
  --debug / --no-debug  Enable debug output for troubleshooting
  --help                Show this message and exit
```

## Usage Examples

### Send a test event

```bash
docker run -e DD_API_KEY=your_api_key_here datadog-events test
```

### Create a custom event interactively

```bash
docker run -it datadog-events create
# You'll be prompted for API key (if not provided), event title, and text
```

### Send events from a file

```bash
docker run -e DD_API_KEY=your_api_key_here -v $(pwd):/app datadog-events file examples/batch_events.json
```

### Send events from stdin

```bash
cat examples/batch_events.json | docker run -e DD_API_KEY=your_api_key_here -i datadog-events stdin
```

### Send events with a delay between them

```bash
docker run -e DD_API_KEY=your_api_key_here -v $(pwd):/app datadog-events --interval 5 file examples/batch_events.yaml
```

### Troubleshooting API issues

If you're having trouble connecting to the Datadog API, use the debug flag:

```bash
docker run -e DD_API_KEY=your_api_key_here datadog-events --debug test
```

## Simplified Usage with run.sh

For convenience, a run.sh script is provided that handles Docker commands:

```bash
# First, export your API key (optional - will prompt if not set)
export DD_API_KEY=your_api_key_here

# For email features, export your SendGrid API key
export SENDGRID_API_KEY=your_sendgrid_api_key

# Optionally, set your Datadog site if not using US site
export DD_SITE=api.datadoghq.eu

# Build/rebuild options
./run.sh --rebuild         # Delete existing image and rebuild it
./run.sh --force-rebuild   # Rebuild image with --no-cache

# Send a test event
./run.sh test

# Create an event interactively
./run.sh create

# Send events from a file with 2-second intervals
./run.sh --interval 2 file examples/event_template.json

# Run a complete scenario (API and email events)
./run.sh scenario --scenario-dir examples/scenarios/scenario1

# Debug mode for troubleshooting
./run.sh --debug test
```

## Event Format

Events are specified in JSON format. All available fields are documented in the example templates:

- [JSON Template](examples/event_template.json) 

Here's a basic example:

```json
{
  "events": [
    {
      "title": "Event Title",
      "text": "Detailed description of the event",
      "tags": ["tag1:value1", "tag2:value2", "source:synthetic"],
      "alert_type": "info",
      "priority": "normal",
      "source_type_name": "synthetic",
      "host": "hostname",
      "device_name": "device",
      "aggregation_key": "group_events"
    }
  ]
}
```

## Available Event Properties

| Property | Required | Description | Example Values |
|----------|----------|-------------|----------------|
| title | Yes | Short event title | "API Service Down" |
| text | Yes | Detailed event description | "The payment API is returning 500 errors" |
| tags | No | List of tags for filtering | ["env:prod", "service:api"] |
| alert_type | No | Event severity | "info", "warning", "error", "success" |
| priority | No | Event priority | "normal", "low" |
| source_type_name | No | Custom source name (SOURCE field) | "synthetic" |
| host | No | Host that generated the event | "web-server-01" |
| device_name | No | Device that generated the event | "load-balancer-02" |
| aggregation_key | No | Key to group related events | "deployment-123" |

## Email Integration

The tool supports two ways of handling email alert content:

1. **Email-to-Event Conversion**: Simulating email alerts (like those from monitoring systems) and converting them to Datadog events
2. **Email-to-Log Conversion**: Processing email content as Datadog logs for better parsing in Log Management

Both features require a SendGrid API key for the email sending portion.

### Environment Variables for Email

- `SENDGRID_API_KEY` (required for email features): Your SendGrid API key
- `DD_EMAIL_ADDRESS` (optional): Custom Datadog email address for email-to-event conversion

### Email Templates and Scenarios

Templates and scenarios are defined in JSON format:

- Email-to-Event templates: `examples/scenarios/*/email_events.json`
- Email-to-Log templates: `examples/scenarios/*/email_logs.json` 
- API events: `examples/scenarios/*/api_events.json`

### Sending Email Alerts

```bash
# Export your SendGrid API key and Datadog email address
export SENDGRID_API_KEY=your_sendgrid_api_key
export DD_EMAIL_ADDRESS=your-integration-key@dtdg.co

# Send a single email alert
./run.sh email --template examples/scenarios/scenario1/email_events.json

# Send a saved email file directly to Datadog
./run.sh send_email_file ./data/datadog_email_20250508_161846.eml
```

### Running Complete Scenarios

The scenario command lets you run both API events and email integrations from a scenario directory:

```bash
# Export your API keys
export DD_API_KEY=your_datadog_api_key
export SENDGRID_API_KEY=your_sendgrid_api_key

# Run the complete scenario (API events, email alerts, and email logs)
./run.sh scenario --scenario-dir examples/scenarios/scenario1

# Customize the interval between events
./run.sh scenario --scenario-dir examples/scenarios/scenario1 --interval 5

# Run only the logs portion of a scenario (skips API events and email events)
./run.sh scenario --scenario-dir examples/scenarios/scenario1 --logs-only

# Skip only the API events portion
./run.sh scenario --scenario-dir examples/scenarios/scenario1 --skip-api-events

# Skip only the email events portion
./run.sh scenario --scenario-dir examples/scenarios/scenario1 --skip-email-events
```

### Log Format

When using email content as logs (via `email_logs.json`), the following format is used:

```json
{
  "events": [
    {
      "timestamp": "2025-02-21T10:14:57",
      "source": "toyota_monitoring_system",
      "service": "infrastructure_monitoring",
      "hostname": "dc2-uvadcep01",
      "tags": ["environment:production", "alert_type:communication_lost", "severity:critical"],
      "content": "Alert Title: TMA Washington DC 11th Floor IDF..."
    }
  ]
}
```

| Property | Description | Example Values |
|----------|-------------|----------------|
| timestamp | Log timestamp (ISO 8601 format) | "2025-02-21T10:14:57" |
| source | Source of the log (ddsource) | "toyota_monitoring_system" |
| service | Service name (service) | "infrastructure_monitoring" |
| hostname | Host generating the log | "dc2-uvadcep01" |
| tags | Array of tags for filtering | ["environment:production"] |
| content | The log message content | "Alert Title: TMA Washington..." |

### Pre-configured Scenarios

The tool comes with pre-configured scenarios that demonstrate different use cases:

- **Scenario 1**: NetBotz communication lost alert
  - Demonstrates API events, email alerts, and email logs for the same event
- **Scenario 2**: Application performance monitoring alert
  - Shows a high latency alert from a payment processing API
  - Provides examples of warning-level alerts with performance metrics
  - Includes different tag taxonomies for application monitoring

You can use these as a starting point for creating your own scenarios.