#!/usr/bin/env python3

import json
import os
import sys
import time
import click
import yaml
from datadog import initialize, api
import logging # Added for email sending
import sendgrid # Added for email sending
from sendgrid.helpers.mail import Mail # Added for email sending
import random
import datetime
import argparse
import datadog
import requests

# Setup basic logging - might conflict if email_sender also does this.
# Let's ensure it's configured once.
# If this script is the main entry, configure here.
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Email Sending Configuration (moved from email_sender.py) ---
SENDER_EMAIL_FALLBACK = "dirk@quickstark.com"
SENDER_EMAIL = os.environ.get('SENDER_EMAIL_ADDRESS', SENDER_EMAIL_FALLBACK)
# SENDGRID_API_KEY will be handled by Click options or env var directly in functions needing it.


# --- Core Email Sending Logic (moved from email_sender.py and adapted) ---
def _send_datadog_scenario_email(sendgrid_api_key: str, subject: str, body: str, recipient_email: str) -> bool:
    """Sends a single email for a scenario using SendGrid.

    Args:
        sendgrid_api_key: The SendGrid API key.
        subject: The subject of the email.
        body: The plain text content of the email.
        recipient_email: The email address of the recipient.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    if not sendgrid_api_key:
        logger.error("SendGrid API key not provided to _send_datadog_scenario_email, cannot send email.")
        return False
    if not recipient_email:
        logger.error("Recipient email not provided to _send_datadog_scenario_email, cannot send email.")
        return False

    logger.info(f"Preparing to send email. To: {recipient_email}, From: {SENDER_EMAIL}, Subject: {subject}")

    try:
        message = Mail(
            from_email=SENDER_EMAIL,
            to_emails=recipient_email,
            subject=subject,
            plain_text_content=body
        )
        
        sg = sendgrid.SendGridAPIClient(api_key=sendgrid_api_key)
        response = sg.send(message)
        
        status_code = response.status_code
        if 200 <= status_code < 300:
            logger.info(f"Email sent successfully to {recipient_email} (Subject: {subject}, Status: {status_code})")
            print(f"✓ Email sent successfully to {recipient_email} (Subject: {subject}, Status: {status_code})")
            return True
        else:
            logger.error(f"SendGrid returned non-successful status code: {status_code} for {recipient_email}. Body: {response.body}")
            print(f"✗ Failed to send email to {recipient_email} (Status: {status_code}). Check logs.")
            return False
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email} via SendGrid: {str(e)}", exc_info=True)
        print(f"✗ Exception while sending email to {recipient_email}. Check logs.")
        return False

def _handle_datadog_api_response(ctx, result):
    """Handles the response from a Datadog API call.

    Prints relevant information, checks for errors, and exits if necessary.

    Args:
        ctx: The Click context object.
        result (dict): The response dictionary from the Datadog API.
    """
    if not result:
        click.echo("Failed to get a response from Datadog API.", err=True)
        ctx.exit(1)

    if ctx.obj.get('debug', False) or 'errors' in result:
        click.echo(f"Full response: {json.dumps(result, indent=2)}")
    else:
        click.echo(f"Response structure: {list(result.keys())}")

    if 'errors' in result:
        click.echo(f"Error from Datadog API: {result['errors']}", err=True)
        ctx.exit(1)

    event_id = result.get('id')
    event_url = None

    if 'event' in result and isinstance(result['event'], dict):
        event_data = result['event']
        event_id = event_data.get('id', event_id)
        event_url = event_data.get('url')
    
    if not event_id and 'status' in result:
        event_id = f"Status: {result['status']}"
    
    event_id = event_id or "unknown" # Default to unknown if still not set

    click.echo(f"Event action successful (ID: {event_id})")
    if event_url:
        click.echo(f"View event at: {event_url}")

def send_event(event, dd_options):
    """Sends a single event to Datadog.

    Args:
        event (dict): A dictionary representing the event to send.
                      Expected keys include 'title', 'text', 'tags', 'alert_type',
                      'priority', 'host', 'device_name', 'aggregation_key',
                      and 'source_type_name'.
        dd_options (dict): A dictionary containing Datadog API options,
                           including 'api_key', 'app_key', and 'api_host'.

    Returns:
        dict: The API response from Datadog if successful, None otherwise.
    """
    try:
        # Initialize with provided options
        initialize(**dd_options)
        
        api_key = dd_options.get('api_key', 'not provided')
        if api_key and len(api_key) > 8:
            masked_key = f"{api_key[:4]}...{api_key[-4:]}"
        else:
            masked_key = "invalid or missing"
        click.echo(f"Using Datadog API key: {masked_key}")
        click.echo(f"API Host: {dd_options.get('api_host', 'default')}")

        # Determine title to send to Datadog API
        title_from_json = event.get('title')
        # If title from JSON is None or effectively empty, send "" to let Datadog auto-generate.
        title_for_api = title_from_json if title_from_json and title_from_json.strip() else ""

        # Determine text to send to Datadog API
        text_from_json = event.get('text')
        text_for_api = "" # Initialize

        if text_from_json and text_from_json.strip():
            # 1. JSON text is valid and non-empty, use it directly.
            text_for_api = text_from_json
            logger.info(f"Using text from JSON for event message for title ('{title_for_api or 'auto-generated'}').")
        else:
            # 2. JSON text is empty/missing. Fallback needed.
            # Use a non-empty version of the JSON title as the message.
            # If JSON title is also empty/whitespace, use a hardcoded default.
            effective_title_for_message = title_from_json if title_from_json and title_from_json.strip() else "Untitled Event"
            text_for_api = effective_title_for_message
            logger.info(f"Event text from JSON was empty/missing for title ('{title_for_api or 'auto-generated'}'); using effective title ('{effective_title_for_message}') as event message.")
            
            # Absolute fallback if the above somehow still results in empty text_for_api
            if not text_for_api or not text_for_api.strip():
                text_for_api = "Event occurred. See title and tags for details."
                logger.warning(f"Effective title for message was also empty for title ('{title_for_api or 'auto-generated'}'); using hardcoded default message: '{text_for_api}'")

        # Send the event
        response = api.Event.create(
            title=title_for_api, # This can be "" to allow Datadog to auto-generate title
            text=text_for_api,   # This should now always be a non-empty string
            tags=event.get('tags', []),
            alert_type=event.get('alert_type', 'info'),
            priority=event.get('priority', 'normal'),
            host=event.get('host'),
            device_name=event.get('device_name'),
            aggregation_key=event.get('aggregation_key'),
            source_type_name=event.get('source_type_name', 'simulator')
        )
        return response
    except Exception as e:
        click.echo(f"Error sending event: {e}", err=True)
        return None

def process_batch(events, dd_options, interval=0):
    """Processes a batch of events and sends them to Datadog.

    Args:
        events (list): A list of event dictionaries to send.
        dd_options (dict): Datadog API options.
        interval (float, optional): Time in seconds to wait between sending
                                     each event. Defaults to 0.

    Returns:
        list: A list of API responses from Datadog for each event.
    """
    results = []
    
    with click.progressbar(events, label='Sending events') as progress_events:
        for event in progress_events:
            # Ensure each event has source_type_name set if not already
            if 'source_type_name' not in event:
                event['source_type_name'] = 'simulator'
                
            result = send_event(event, dd_options)
            results.append(result)
            
            # Sleep between events if interval is specified
            if interval > 0 and event != events[-1]:
                time.sleep(interval)
    
    return results

def load_events_from_file(file_path):
    """Loads events from a JSON or YAML file.

    The file can be a list of event objects or an object with an 'events' key
    containing a list of event objects.

    Args:
        file_path (str): The path to the JSON or YAML file.

    Returns:
        list: A list of event dictionaries.

    Raises:
        click.UsageError: If the file format is invalid, or if there's an
                          error parsing or loading the file.
        click.FileError: If the file is not found.
    """
    try:
        with open(file_path, 'r') as f:
            if file_path.lower().endswith('.yaml') or file_path.lower().endswith('.yml'):
                content = yaml.safe_load(f)
            else:  # Default to JSON
                content = json.load(f)
            
            # Check if the file has an 'events' key (array of events)
            if 'events' in content and isinstance(content['events'], list):
                return content['events']
            elif isinstance(content, list):
                return content
            else:
                raise click.UsageError(f"Invalid file format. Expected an array of events or an object with an 'events' array.")
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise click.UsageError(f"Error parsing {file_path}: {e}")
    except FileNotFoundError:
        raise click.FileError(file_path, hint="File not found")
    except Exception as e:
        raise click.UsageError(f"Error loading events from {file_path}: {e}")

def load_events_from_stdin():
    """Loads events from stdin (JSON or YAML format).

    The input can be a list of event objects or an object with an 'events' key
    containing a list of event objects.

    Returns:
        list: A list of event dictionaries.

    Raises:
        click.UsageError: If the input format is invalid or if there's an
                          error parsing the input.
    """
    try:
        content = sys.stdin.read()
        
        # Try parsing as JSON first
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # If JSON parsing fails, try YAML
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise click.UsageError(f"Error parsing input as YAML: {e}")
        
        # Check if the content has an 'events' key (array of events)
        if 'events' in data and isinstance(data['events'], list):
            return data['events']
        elif isinstance(data, list):
            return data
        else:
            raise click.UsageError("Invalid input format. Expected an array of events or an object with an 'events' array.")
    except Exception as e:
        raise click.UsageError(f"Error loading events from stdin: {e}")

def process_tags_input(tags_input):
    """Processes a comma-separated string of tags into a list of tags.

    Args:
        tags_input (str): A comma-separated string of tags (e.g., "key1:value1,key2:value2").

    Returns:
        list: A list of cleaned tag strings. Returns an empty list if
              tags_input is None or empty.
    """
    if not tags_input:
        return []
        
    tag_list = []
    for tag in tags_input.split(','):
        tag = tag.strip()
        if tag:
            tag_list.append(tag)
    
    return tag_list

@click.group()
@click.option('--interval', default=0.0, type=float, help='Interval between events in seconds')
@click.option('--api-key', envvar='DD_API_KEY', help='Datadog API key (can also use DD_API_KEY env var)')
@click.option('--app-key', envvar='DD_APP_KEY', help='Datadog application key (can also use DD_APP_KEY env var)')
@click.option('--site', envvar='DD_SITE', default='api.datadoghq.com', help='Datadog site (can also use DD_SITE env var)')
@click.option('--debug/--no-debug', default=False, help='Enable debug output for troubleshooting')
@click.pass_context
def cli(ctx, interval, api_key, app_key, site, debug):
    """A command-line tool for sending synthetic events to Datadog.

    This tool allows for sending individual events, batches of events from files
    or stdin, and running predefined scenarios.
    """
    ctx.ensure_object(dict)
    
    # Store options in click context
    ctx.obj['interval'] = interval
    ctx.obj['debug'] = debug
    
    # Set up Datadog API options
    if not api_key:
        api_key = os.environ.get('DD_API_KEY')
        if not api_key:
            api_key = click.prompt('Datadog API key', hide_input=True)
    
    ctx.obj['dd_options'] = {
        'api_key': api_key,
        'app_key': app_key,
        'api_host': f"https://{site}"
    }
    
    if debug:
        click.echo(f"Debug mode enabled")
        click.echo(f"Using Datadog site: {site}")
        click.echo(f"API host: {ctx.obj['dd_options']['api_host']}")

@cli.command()
@click.pass_context
def test(ctx):
    """Sends a single pre-defined test event to Datadog.

    This command is useful for quickly verifying the connection and
    configuration with Datadog.
    """
    # Create a test event
    event = {
        'title': "Test Event",
        'text': "This is a test event from the Datadog Events simulator.",
        'tags': ["source:simulator", "type:test"],
        'alert_type': 'info',
        'priority': 'normal',
        'source_type_name': 'simulator'
    }
    
    # Send the event
    click.echo("Sending test event to Datadog...")
    result = send_event(event, ctx.obj['dd_options'])
    
    if result:
        # Debug output
        if ctx.obj['debug'] or 'errors' in result:
            click.echo(f"Full response: {json.dumps(result, indent=2)}")
        else:
            click.echo(f"Response structure: {list(result.keys())}")
        
        # Check for errors
        if 'errors' in result:
            click.echo(f"Error from Datadog API: {result['errors']}", err=True)
            ctx.exit(1)
        
        # Try to find an ID in the response
        event_id = 'unknown'
        if 'id' in result:
            event_id = result['id']
        elif 'event' in result and isinstance(result['event'], dict):
            event_id = result['event'].get('id', 'unknown')
        elif 'status' in result:
            event_id = f"Status: {result['status']}"
            
        # If we have a URL, display it
        event_url = None
        if 'event' in result and isinstance(result['event'], dict) and 'url' in result['event']:
            event_url = result['event']['url']
            
        click.echo(f"Test event sent successfully (ID: {event_id})")
        if event_url:
            click.echo(f"View event at: {event_url}")
    else:
        click.echo("Failed to send test event", err=True)
        ctx.exit(1)

@cli.command()
@click.argument('file', type=click.Path(exists=True, readable=True))
@click.pass_context
def file(ctx, file):
    """Sends events to Datadog from a specified JSON or YAML file.

    Args:
        ctx: The Click context object.
        file (str): Path to the file containing events.
    """
    try:
        events = load_events_from_file(file)
    except (click.FileError, click.UsageError) as e:
        click.echo(f"Error: {e}", err=True)
        ctx.exit(1)
    
    click.echo(f"Loaded {len(events)} events from {file}")
    
    # Process the events
    results = process_batch(events, ctx.obj['dd_options'], ctx.obj['interval'])
    
    # Print a summary
    success_count = sum(1 for r in results if r is not None and 'errors' not in r)
    click.echo(f"\nSummary: Sent {success_count}/{len(events)} events successfully")

@cli.command()
@click.pass_context
def stdin(ctx):
    """Sends events to Datadog from stdin (JSON or YAML format).

    Args:
        ctx: The Click context object.
    """
    try:
        events = load_events_from_stdin()
    except click.UsageError as e:
        click.echo(f"Error: {e}", err=True)
        ctx.exit(1)
    
    click.echo(f"Loaded {len(events)} events from stdin")
    
    # Process the events
    results = process_batch(events, ctx.obj['dd_options'], ctx.obj['interval'])
    
    # Print a summary
    success_count = sum(1 for r in results if r is not None and 'errors' not in r)
    click.echo(f"\nSummary: Sent {success_count}/{len(events)} events successfully")

@cli.command()
@click.option('--title', prompt='Event title', help='Title of the event')
@click.option('--text', prompt='Event text', help='Text body of the event')
@click.option('--tags', prompt='Tags (comma-separated, e.g., service:api,env:prod)', default='', help='Comma-separated list of tags (format: key:value)')
@click.option('--alert-type', type=click.Choice(['info', 'warning', 'error', 'success']), 
              default='info', prompt='Alert type [info/warning/error/success]', help='Alert type')
@click.option('--priority', type=click.Choice(['normal', 'low']), 
              default='normal', prompt='Priority [normal/low]', help='Event priority')
@click.option('--source', prompt='Source name', default='simulator', 
              help='Source name for the event')
@click.option('--host', help='Source host name')
@click.pass_context
def create(ctx, title, text, tags, alert_type, priority, source, host):
    """Creates and sends a single custom event to Datadog based on user prompts.

    Args:
        ctx: The Click context object.
        title (str): Title of the event.
        text (str): Text body of the event.
        tags (str): Comma-separated list of tags (e.g., "service:api,env:prod").
        alert_type (str): Alert type ('info', 'warning', 'error', 'success').
        priority (str): Event priority ('normal', 'low').
        source (str): Source name for the event.
        host (str, optional): Source host name.
    """
    # Process tags if provided
    tag_list = process_tags_input(tags)
    
    # Add source tag if not already present
    if source and not any(tag.startswith('source:') for tag in tag_list):
        tag_list.append(f"source:{source}")
    
    # Create the event
    event = {
        'title': title,
        'text': text,
        'tags': tag_list,
        'alert_type': alert_type,
        'priority': priority,
        'source_type_name': source  # Set source type directly
    }
    
    # Add host if provided
    if host:
        event['host'] = host
    
    # Send the event
    click.echo(f"Sending event with tags: {tag_list}")
    click.echo(f"Source: {source}")
    result = send_event(event, ctx.obj['dd_options'])
    
    if result:
        # Debug output
        if ctx.obj['debug'] or 'errors' in result:
            click.echo(f"Full response: {json.dumps(result, indent=2)}")
        else:
            click.echo(f"Response structure: {list(result.keys())}")
        
        # Check for errors
        if 'errors' in result:
            click.echo(f"Error from Datadog API: {result['errors']}", err=True)
            ctx.exit(1)
        
        # Try to find an ID in the response
        event_id = 'unknown'
        if 'id' in result:
            event_id = result['id']
        elif 'event' in result and isinstance(result['event'], dict):
            event_id = result['event'].get('id', 'unknown')
        elif 'status' in result:
            event_id = f"Status: {result['status']}"
            
        # If we have a URL, display it
        event_url = None
        if 'event' in result and isinstance(result['event'], dict) and 'url' in result['event']:
            event_url = result['event']['url']
            
        click.echo(f"Event sent successfully (ID: {event_id})")
        if event_url:
            click.echo(f"View event at: {event_url}")
    else:
        click.echo("Failed to send event", err=True)
        ctx.exit(1)

@cli.command()
@click.option('--scenario-dir', 
              type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True), 
              required=True, 
              help='Directory containing scenario files (e.g., api_events.json, email_events.json, logs.json)')
@click.option('--sendgrid-api-key', 
              envvar='SENDGRID_API_KEY', 
              help='SendGrid API key for email events. Overrides SENDGRID_API_KEY env var.')
@click.option('--email-recipient-override', 
              help='Optional: Override recipient email address for ALL email events in this scenario run.')
@click.option('--interval', type=float, default=None, help='Interval in seconds between events. Overrides main interval for this scenario.')
@click.option('--skip-api-events', is_flag=True, help='Skip processing API events.')
@click.option('--skip-email-events', is_flag=True, help='Skip processing email events.')
@click.option('--logs-only', is_flag=True, help='Process only logs files (skips both API and email events).')
@click.pass_context
def scenario(ctx, scenario_dir, sendgrid_api_key, email_recipient_override, interval, skip_api_events, skip_email_events, logs_only):
    """Runs a scenario by processing event files from a specified directory.

    A scenario can include API events, email events, and log submissions.
    It looks for `api_events.json`, `email_events.json`, and `*.log.json` or `*.log.yaml` files
    within the `scenario_dir`.

    Args:
        ctx: The Click context object.
        scenario_dir (str): Directory containing scenario files.
        sendgrid_api_key (str, optional): SendGrid API key for email events.
        email_recipient_override (str, optional): Override recipient email for all email events.
        interval (float, optional): Interval between sending events. Overrides global interval.
        skip_api_events (bool): If True, skip processing API events.
        skip_email_events (bool): If True, skip processing email events.
        logs_only (bool): If True, process only log files.
    """
    click.echo(f"\n--- Running Scenario from Directory: {scenario_dir} ---")
    
    # If logs-only is set, skip both API and email events
    if logs_only:
        skip_api_events = True
        skip_email_events = True
    
    # Determine interval: command-specific, then main context, then default
    scenario_interval = interval if interval is not None else ctx.obj.get('interval', 0.5) # Default to 0.5s if no other interval set

    logger.info(f"Running scenario from directory: {scenario_dir} with interval: {scenario_interval}s")
    logger.info(f"Sender email for scenarios: {SENDER_EMAIL}")
    if email_recipient_override:
        logger.info(f"Email recipient override for this scenario run: {email_recipient_override}")
    if logs_only:
        logger.info("Processing only logs (skipping API and email events)")
    else:
        if skip_api_events:
            logger.info("Skipping API events as requested")
        if skip_email_events:
            logger.info("Skipping email events as requested")

    api_events_path = os.path.join(scenario_dir, 'api_events.json')
    email_events_path = os.path.join(scenario_dir, 'email_events.json')
    email_logs_path = os.path.join(scenario_dir, 'email_logs.json')
    logs_path = os.path.join(scenario_dir, 'logs.json')
    
    api_events_exist = os.path.isfile(api_events_path)
    email_events_exist = os.path.isfile(email_events_path)
    email_logs_exist = os.path.isfile(email_logs_path)
    logs_exist = os.path.isfile(logs_path)
    
    if not logs_only and not api_events_exist and not email_events_exist and not email_logs_exist and not logs_exist:
        click.echo(f"Error: No api_events.json, email_events.json, email_logs.json, or logs.json found in {scenario_dir}", err=True)
        logger.error(f"No valid scenario files found in {scenario_dir}")
        ctx.exit(1)
    
    if logs_only and not email_logs_exist and not logs_exist:
        click.echo(f"Error: No logs.json or email_logs.json found in {scenario_dir} when running with --logs-only", err=True)
        logger.error(f"No log files found in {scenario_dir} when running with --logs-only")
        ctx.exit(1)
        
    # Step 1: Process API Events if they exist and not skipped
    if not skip_api_events:
        _process_api_events_from_scenario(ctx, api_events_path, ctx.obj['dd_options'], scenario_interval)
    elif api_events_exist and skip_api_events: # Still log if skipped but file exists
        click.echo("Skipping API events as requested.")
        logger.info(f"Skipping API events as requested (file found: {api_events_path}).")
    
    # Step 2: Wait a bit between API and email events if both exist
    # Check if API events were processed (not skipped AND file existed) and email events might be processed
    api_events_were_processed = not skip_api_events and os.path.isfile(api_events_path)
    potential_email_processing = not skip_email_events and os.path.isfile(email_events_path)

    if api_events_were_processed and potential_email_processing and scenario_interval > 0:
        click.echo(f"Waiting {scenario_interval} seconds before sending email events...")
        time.sleep(scenario_interval)
    
    # Step 3: Process Email Events if they exist
    if email_events_exist and not skip_email_events:
        click.echo(f"Processing email events from: {email_events_path}")
        logger.info(f"Processing email events from: {email_events_path}")
        
        if not sendgrid_api_key:
            # Check env var as a fallback if not provided via option
            sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
            if not sendgrid_api_key:
                click.echo("Error: SendGrid API key is required for email events. "
                           "Set it via --sendgrid-api-key option or SENDGRID_API_KEY environment variable.", err=True)
                logger.error("SendGrid API key missing for email events processing.")
                if not logs_only:  # Only exit if we're not in logs-only mode
                    ctx.exit(1)
                else:
                    click.echo("Continuing with logs processing since --logs-only was specified.")
                    skip_email_events = True  # Skip further email processing
        
        if not skip_email_events:  # Continue only if we shouldn't skip email events
            if len(sendgrid_api_key) > 10:
                logger.info(f"Using SendGrid API key for scenario emails: {sendgrid_api_key[:4]}...{sendgrid_api_key[-4:]}")
            else:
                logger.warning("SendGrid API key for scenario emails appears very short or might be invalid.")

            try:
                with open(email_events_path, 'r') as f:
                    email_scenario_data = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from email_events file {email_events_path}: {e}")
                click.echo(f"Error: Invalid JSON in {email_events_path}.", err=True)
                ctx.exit(1)
            except Exception as e:
                logger.error(f"Error reading email_events file {email_events_path}: {e}")
                click.echo(f"Error: Could not read email_events file {email_events_path}.", err=True)
                ctx.exit(1)

            emails_to_process = email_scenario_data.get('emails')
            if not isinstance(emails_to_process, list):
                logger.error(f"Email scenario file {email_events_path} must contain an 'emails' list.")
                click.echo(f"Error: Email scenario file {email_events_path} must contain an 'emails' list.", err=True)
                ctx.exit(1)

            email_delay_seconds = email_scenario_data.get('delay_seconds', scenario_interval) # Use scenario_interval as default for emails too
            if not isinstance(email_delay_seconds, (int, float)) or email_delay_seconds < 0:
                logger.warning(f"Invalid 'delay_seconds' in email_events ({email_delay_seconds}), defaulting to {scenario_interval}s.")
                email_delay_seconds = scenario_interval
                
            total_emails = len(emails_to_process)
            emails_sent_successfully = 0
            emails_failed_count = 0

            if total_emails == 0:
                logger.info("No emails found in the email_events.json file.")
                click.echo("No emails to send in the email_events.json file.")
            else:
                click.echo(f"Loaded {total_emails} email events to process.")
                with click.progressbar(emails_to_process, label='Sending scenario emails') as progress_emails:
                    for i, email_config in enumerate(progress_emails):
                        logger.info(f"Processing email {i+1}/{total_emails} from scenario...")
                        
                        template_data = email_config.get('template')
                        if not isinstance(template_data, dict):
                            logger.warning(f"Skipping email {i+1} in scenario due to missing or invalid 'template' object.")
                            emails_failed_count += 1
                            continue
                        
                        # Determine recipient: override, then template, then DD_EMAIL_ADDRESS env var as last resort
                        recipient = email_recipient_override or \
                                      template_data.get('to_email') or \
                                      os.environ.get('DD_EMAIL_ADDRESS') 
                                      # The DD_EMAIL_ADDRESS here is a final fallback if template is incomplete
                        
                        subject = template_data.get('subject')
                        body = template_data.get('content')

                        if not all([recipient, subject, body is not None]):
                            logger.warning(f"Skipping email {i+1} in scenario due to missing recipient, subject, or content.")
                            emails_failed_count += 1
                            continue
                        
                        variables = email_config.get('variables', {})
                        if isinstance(variables, dict) and variables:
                            for key, value in variables.items():
                                placeholder = f"{{{{ {key} }}}}"
                                if isinstance(subject, str): subject = subject.replace(placeholder, str(value))
                                if isinstance(body, str): body = body.replace(placeholder, str(value))

                        if _send_datadog_scenario_email(sendgrid_api_key, subject, body, recipient):
                            emails_sent_successfully += 1
                        else:
                            emails_failed_count += 1

                        if i < total_emails - 1 and email_delay_seconds > 0:
                            logger.info(f"Waiting for {email_delay_seconds} seconds before next scenario email...")
                            time.sleep(email_delay_seconds)
                
                click.echo(f"Email Events Summary: Sent {emails_sent_successfully}/{total_emails}. Failed: {emails_failed_count}.")
                logger.info(f"Email Events Summary: Sent {emails_sent_successfully}/{total_emails}. Failed: {emails_failed_count}.")
    elif email_events_exist and skip_email_events:
        click.echo("Skipping email events as requested.")
        logger.info("Skipping email events as requested.")
    
    # Step 4: Process Email Logs if they exist
    if email_logs_exist:
        click.echo(f"Processing email logs from: {email_logs_path}")
        logger.info(f"Processing email logs from: {email_logs_path}")
        
        try:
            # Set up log arguments
            log_args = {
                "source": "synthetic-email", 
                "service": "synthetic-events",
                "api_key": ctx.obj['dd_options'].get('api_key'),
                "site": ctx.obj['dd_options'].get('api_host', '').replace('https://', '').replace('http://', ''),
                "debug": ctx.obj['debug']  # Pass through debug flag
            }
            
            # Log important information for debugging
            api_key = log_args.get('api_key')
            if api_key and len(api_key) > 8:
                masked_key = f"{api_key[:4]}...{api_key[-4:]}"
                logger.info(f"Using API key {masked_key} for email logs")
            
            site = log_args.get('site')
            logger.info(f"Using site {site} for email logs")
            
            # Process the logs
            with open(email_logs_path, 'r') as f:
                data = json.load(f)
                
            if 'events' not in data or not isinstance(data['events'], list):
                logger.error(f"Email logs file {email_logs_path} must contain an 'events' list.")
                click.echo(f"Error: Email logs file {email_logs_path} must contain an 'events' list.", err=True)
            else:
                log_events = data['events']
                total_logs = len(log_events)
                logs_sent_successfully = 0
                logs_failed_count = 0
                
                if total_logs == 0:
                    logger.info("No logs found in the email_logs.json file.")
                    click.echo("No logs to send in the email_logs.json file.")
                else:
                    click.echo(f"Loaded {total_logs} email logs to process.")
                    with click.progressbar(log_events, label='Sending email logs') as progress_logs:
                        for i, log_data in enumerate(progress_logs):
                            try:
                                # If log_data doesn't have a source, add synthetic-email explicitly
                                if "source" not in log_data:
                                    log_data["source"] = "synthetic-email"
                                
                                result = send_log(log_data, log_args)
                                logger.info(f"Email log {i+1} result: {result}")
                                
                                if result.get('status') == 'success':
                                    logs_sent_successfully += 1
                                else:
                                    logs_failed_count += 1
                                    logger.warning(f"Failed to send email log {i+1}: {result}")
                                
                                # Add delay between logs if interval is set
                                if i < total_logs - 1 and scenario_interval > 0:
                                    time.sleep(scenario_interval)
                            except Exception as e:
                                logs_failed_count += 1
                                logger.error(f"Error sending email log {i+1}: {e}")
                    
                    click.echo(f"Email Logs Summary: Sent {logs_sent_successfully}/{total_logs}. Failed: {logs_failed_count}.")
                    logger.info(f"Email Logs Summary: Sent {logs_sent_successfully}/{total_logs}. Failed: {logs_failed_count}.")
        
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from email logs file {email_logs_path}: {e}")
            click.echo(f"Error: Invalid JSON in {email_logs_path}.", err=True)
        except Exception as e:
            logger.error(f"Error processing email logs: {e}")
            click.echo(f"Error processing email logs: {e}", err=True)
    
    # Step 5: Process General Logs if they exist
    if logs_exist:
        click.echo(f"Processing general logs from: {logs_path}")
        logger.info(f"Processing general logs from: {logs_path}")
        
        try:
            # Set up log arguments
            log_args = {
                "source": "synthetic-test", 
                "service": "synthetic-events",
                "api_key": ctx.obj['dd_options'].get('api_key'),
                "site": ctx.obj['dd_options'].get('api_host', '').replace('https://', '').replace('http://', ''),
                "debug": ctx.obj['debug']  # Pass through debug flag
            }
            
            # Log important information for debugging
            api_key = log_args.get('api_key')
            if api_key and len(api_key) > 8:
                masked_key = f"{api_key[:4]}...{api_key[-4:]}"
                logger.info(f"Using API key {masked_key} for general logs")
            
            site = log_args.get('site')
            logger.info(f"Using site {site} for general logs")
            
            # Process the logs
            with open(logs_path, 'r') as f:
                data = json.load(f)
                
            if 'events' not in data or not isinstance(data['events'], list):
                logger.error(f"Logs file {logs_path} must contain an 'events' list.")
                click.echo(f"Error: Logs file {logs_path} must contain an 'events' list.", err=True)
            else:
                log_events = data['events']
                total_logs = len(log_events)
                logs_sent_successfully = 0
                logs_failed_count = 0
                
                if total_logs == 0:
                    logger.info("No logs found in the logs.json file.")
                    click.echo("No logs to send in the logs.json file.")
                else:
                    click.echo(f"Loaded {total_logs} general logs to process.")
                    with click.progressbar(log_events, label='Sending general logs') as progress_logs:
                        for i, log_data in enumerate(progress_logs):
                            try:
                                # If log_data doesn't have a source, add synthetic-test explicitly
                                if "source" not in log_data:
                                    log_data["source"] = "synthetic-test"
                                
                                result = send_log(log_data, log_args)
                                logger.info(f"Log {i+1} result: {result}")
                                
                                if result.get('status') == 'success':
                                    logs_sent_successfully += 1
                                else:
                                    logs_failed_count += 1
                                    logger.warning(f"Failed to send log {i+1}: {result}")
                                
                                # Add delay between logs if interval is set
                                if i < total_logs - 1 and scenario_interval > 0:
                                    time.sleep(scenario_interval)
                            except Exception as e:
                                logs_failed_count += 1
                                logger.error(f"Error sending log {i+1}: {e}")
                    
                    click.echo(f"General Logs Summary: Sent {logs_sent_successfully}/{total_logs}. Failed: {logs_failed_count}.")
                    logger.info(f"General Logs Summary: Sent {logs_sent_successfully}/{total_logs}. Failed: {logs_failed_count}.")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from logs file {logs_path}: {e}")
            click.echo(f"Error: Invalid JSON in {logs_path}.", err=True)
        except Exception as e:
            logger.error(f"Error processing general logs: {e}")
            click.echo(f"Error processing general logs: {e}", err=True)

    click.echo("\nScenario completed!")
    logger.info("Scenario completed successfully!")

@cli.command()
@click.argument('email_file', type=click.Path(exists=True, readable=True))
@click.option('--dd-email', envvar='DD_EMAIL_ADDRESS', help='Override the recipient in the email file')
@click.option('--api-key', envvar='SENDGRID_API_KEY', help='SendGrid API key for sending emails')
@click.pass_context
def send_email_file(ctx, email_file, dd_email, api_key):
    """DEPRECATED: Sends emails defined in a JSON file.

    This command is deprecated. Use the `scenario` command with an `email_events.json`
    file for more robust email scenario handling.

    Args:
        ctx: The Click context object.
        email_file (str): Path to the JSON file containing email definitions.
        dd_email (str, optional): Recipient email address, overrides file content.
        api_key (str, optional): SendGrid API key.
    """
    logger.warning("The 'send-email-file' command is deprecated. Consider using the 'scenario' command with an 'email_events.json' file.")
    
    # Read the email file content
    with open(email_file, 'r') as f:
        content = f.read()
    
    # Check for basic format - if it looks like our saved format
    lines = content.strip().split('\n')
    
    # Default values
    subject = os.path.basename(email_file)  # Use filename as default subject
    to_email = dd_email or os.environ.get('DD_EMAIL_ADDRESS', 'event-8l2d0xg2@dtdg.co')
    email_content = content  # Default to full content
    
    # Try to parse simple format (TO, SUBJECT, CONTENT)
    if len(lines) > 2 and lines[0].startswith('TO:') and lines[1].startswith('SUBJECT:'):
        # Parse our simple format
        to_email = lines[0].replace('TO:', '').strip()
        subject = lines[1].replace('SUBJECT:', '').strip()
        # Content starts after the CONTENT: line
        content_start = content.find('CONTENT:') + 8
        if content_start > 8:  # Found 'CONTENT:'
            email_content = content[content_start:].strip()
        
    # Use provided DD email address if specified
    if dd_email:
        to_email = dd_email
        click.echo(f"Using Datadog email address: {dd_email}")
    
    # Try to send via SendGrid
    click.echo(f"Sending email to {to_email} via SendGrid...")
    
    # Check if we have a SendGrid API key
    if not api_key:
        api_key = os.environ.get('SENDGRID_API_KEY')
        if not api_key:
            click.echo("No SendGrid API key provided. Please set the SENDGRID_API_KEY environment variable or use --api-key.", err=True)
            ctx.exit(1)
    
    try:
        # Create simple message with SendGrid - exact same pattern as working example
        message = Mail(
            from_email="alerts@synthetic-events.simulator",
            to_emails=to_email,
            subject=subject,
            plain_text_content=email_content
        )
        
        # Send the email using SendGrid API - simple approach
        sg = sendgrid.SendGridAPIClient(api_key)
        response = sg.send(message)
        
        # Log the response
        status_code = response.status_code
        if status_code >= 200 and status_code < 300:
            click.echo(f"✓ Email sent successfully to {to_email} (Status: {status_code})")
            return
        else:
            click.echo(f"SendGrid returned non-successful status code: {status_code}", err=True)
            
    except Exception as e:
        click.echo(f"Error sending email: {e}", err=True)
        click.echo("The email file was not sent to Datadog")
        ctx.exit(1)

@cli.command()
@click.pass_context
def test_logs(ctx):
    """Sends a predefined set of test logs to Datadog.

    Useful for verifying the log submission setup.

    Args:
        ctx: The Click context object.
    """
    click.echo("\n--- Sending Test Logs ---")
    
    # Create a test log
    test_log = {
        "content": "Alert Title: TMA Test IDF (10.67.40.163) - communication lost\nAlert Description: Communication with 'TMA Test IDF (10.67.40.163)' has been lost.\nAlert Type: Communication Lost\nSeverity: Critical\nAlert Level: Email Test\nDevice: TMA Test IDF (10.67.40.163)\nTime Detected: 05/10/2025 10:04:57 am\nNotification Time: 05/10/2025 10:14:57 am\nNotification Policy: Email Test\nAction Name: Email Test",
        "source": "synthetic-test",
        "tags": ["test:true", "environment:dev"],
        "hostname": "test-host",
        "service": "synthetic-events"
    }
    
    # Get API key from context
    api_key = ctx.obj['dd_options'].get('api_key')
    if not api_key:
        click.echo("No Datadog API key found. Use --api-key or set DD_API_KEY environment variable.", err=True)
        ctx.exit(1)
    
    # Extract site from context
    site_url = ctx.obj['dd_options'].get('api_host', 'https://api.datadoghq.com')
    # Extract the domain part from the API host
    site = site_url.replace('https://', '').replace('http://', '')
    
    click.echo(f"Using Datadog site: {site}")
    click.echo(f"Using API key: {api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "API key is too short")
    
    # Set up log arguments consistently with other commands
    log_args = {
        "source": "synthetic-test", 
        "service": "synthetic-events",
        "api_key": api_key,
        "site": site,
        "debug": ctx.obj['debug']  # Pass through debug flag
    }
    
    try:
        # Send the log
        click.echo("Sending test log...")
        result = send_log(test_log, log_args)
        click.echo(f"Log sending result: {result}")
        if result.get('status') == 'success':
            click.echo("✓ Test log sent successfully!")
        else:
            click.echo("✗ Failed to send test log.", err=True)
    except Exception as e:
        click.echo(f"Error sending test log: {e}", err=True)
        ctx.exit(1)

def setup_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

def set_datadog_option_envs(options):
    """Sets Datadog related environment variables if not already set.

    This is primarily for internal use by other scripts that might call
    this simulator's functions programmatically.

    Args:
        options (dict): A dictionary containing Datadog options like
                        'api_key', 'app_key', 'api_host'.
    """
    if 'host' in options:
        os.environ['DATADOG_HOST'] = options['host']
    if 'api_key' in options and not os.environ.get('DATADOG_API_KEY'):
        os.environ['DATADOG_API_KEY'] = options['api_key']
    if 'app_key' in options and not os.environ.get('DATADOG_APP_KEY'):
        os.environ['DATADOG_APP_KEY'] = options['app_key']

def init_datadog(options):
    set_datadog_option_envs(options)
    datadog.initialize(
        api_key=os.environ.get('DATADOG_API_KEY'),
        app_key=os.environ.get('DATADOG_APP_KEY'),
        api_host=os.environ.get('DATADOG_HOST', 'https://api.datadoghq.com')
    )

def send_log(log_data, log_args):
    """Sends a single log entry or a batch of log entries to Datadog HTTP intake.

    Args:
        log_data (dict or list): A single log entry (dict) or a list of log entries (list of dicts).
                                 Each log entry should be a dictionary.
        log_args (argparse.Namespace or dict): Arguments containing Datadog configuration
                                               (api_key, site) and log metadata (source, service).
                                               Can be an argparse Namespace or a dictionary.

    Returns:
        requests.Response or None: The response from the Datadog API if the request was made,
                                   otherwise None.

    Raises:
        ValueError: If `log_data` is not a dict or a list of dicts.
    """
    # Ensure log_args can be accessed with .get or ['key']
    api_key = log_args.get('api_key') or os.environ.get('DATADOG_API_KEY') or os.environ.get('DD_API_KEY')
    site = log_args.get('site') or os.environ.get('DD_SITE', 'datadoghq.com')
    
    # Handle site parameter to extract just the domain part
    # Remove 'api.' prefix if present
    if site.startswith('api.'):
        site = site[4:]
    # Remove any protocol prefix (http://, https://)
    site = site.replace('https://', '').replace('http://', '')
    
    # Construct the URL based on site
    url = f"https://http-intake.logs.{site}/api/v2/logs"
    logger.info(f"Sending log to URL: {url}")
    logger.info(f"Using source: {log_args.get('source', 'synthetic-test')}")
    
    # Set headers
    headers = {
        "Content-Type": "application/json",
        "DD-API-KEY": api_key
    }
    
    # Create a list containing the log entry as required by the API
    payload = [log_data]
    
    # Log the payload for debugging
    logger.info(f"Log payload: {json.dumps(payload)}")
    
    # Print request details if debug is enabled
    debug = log_args.get('debug', False)
    if debug:
        print(f"DEBUG: Sending log to URL: {url}")
        print(f"DEBUG: Headers: {headers}")
        print(f"DEBUG: Payload: {json.dumps(payload, indent=2)}")
    
    # Send the request
    try:
        response = requests.post(url, headers=headers, json=payload)
        
        # Print response details if debug is enabled
        if debug:
            print(f"DEBUG: Response status: {response.status_code}")
            print(f"DEBUG: Response content: {response.text}")
        
        # Check response
        if response.status_code in [200, 202]:
            logger.info(f"Log sent successfully: Status {response.status_code}")
            return {"status": "success", "status_code": response.status_code}
        else:
            logger.error(f"Failed to send log: Status {response.status_code}, Response: {response.text}")
            return {"status": "error", "status_code": response.status_code, "message": response.text}
    except Exception as e:
        logger.error(f"Exception sending log: {e}")
        if debug:
            print(f"DEBUG: Exception sending log: {e}")
        return {"status": "error", "message": str(e)}

def get_scenario_file_path(scenario_name, file_name):
    cur_dir = os.path.dirname(os.path.realpath(__file__))
    scenario_dir = os.path.normpath(os.path.join(
        cur_dir, '../examples/scenarios/', scenario_name))
    return os.path.join(scenario_dir, file_name)

def parse_json_file(file_path):
    """Parses a JSON file and returns its content.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict or list: The parsed JSON content.

    Raises:
        SystemExit: If the file is not found or cannot be parsed.
    """
    try:
        with open(file_path, 'r') as f:
            if file_path.lower().endswith('.yaml') or file_path.lower().endswith('.yml'):
                content = yaml.safe_load(f)
            else:  # Default to JSON
                content = json.load(f)
            
            # Check if the file has an 'events' key (array of events)
            if 'events' in content and isinstance(content['events'], list):
                return content['events']
            elif isinstance(content, list):
                return content
            else:
                raise click.UsageError(f"Invalid file format. Expected an array of events or an object with an 'events' array.")
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise click.UsageError(f"Error parsing {file_path}: {e}")
    except FileNotFoundError:
        raise click.FileError(file_path, hint="File not found")
    except Exception as e:
        raise click.UsageError(f"Error loading events from {file_path}: {e}")

def run_event_file(file_path, event_args):
    """DEPRECATED: Runs events from a specified file.

    This function is deprecated. Use the `file` command or `scenario` command.

    Args:
        file_path (str): Path to the event file.
        event_args (dict): Arguments for event processing.
    """
    print(f"Running event file: {file_path}")
    data = parse_json_file(file_path)

    for evt in data['events']:
        try:
            result = send_event(evt, event_args)
            logger.info(f"Event result: {result}")
        except Exception as e:
            logger.error(f"Failed to send event: {e}")
            raise
    print(f"Log file processed: {file_path}")

def run_scenario(scenario_name, event_args):
    """DEPRECATED: Runs a specific scenario by name.

    This function is deprecated. Use the `scenario` command with a directory.

    Args:
        scenario_name (str): The name of the scenario to run.
        event_args (dict): Arguments for event processing.
    """
    # Check for email_events.json
    email_events_path = get_scenario_file_path(scenario_name, 'email_events.json')
    if os.path.exists(email_events_path):
        run_event_file(email_events_path, event_args)

    # Check for email_logs.json
    email_logs_path = get_scenario_file_path(scenario_name, 'email_logs.json')
    if os.path.exists(email_logs_path):
        # Include API credentials from event_args
        log_args = {
            "source": "synthetic-email", 
            "service": "synthetic-events",
            "api_key": event_args.get('api_key'),
            "site": event_args.get('api_host', '').replace('https://', '').replace('http://', ''),
            "debug": event_args.get('debug', False)  # Pass through debug flag
        }
        run_log_file(email_logs_path, log_args)
        
    # Check for logs.json (general purpose logs)
    logs_path = get_scenario_file_path(scenario_name, 'logs.json')
    if os.path.exists(logs_path):
        # Include API credentials from event_args
        log_args = {
            "source": "synthetic-test", 
            "service": "synthetic-events",
            "api_key": event_args.get('api_key'),
            "site": event_args.get('api_host', '').replace('https://', '').replace('http://', ''),
            "debug": event_args.get('debug', False)  # Pass through debug flag
        }
        logger.info(f"Processing general logs from: {logs_path}")
        run_log_file(logs_path, log_args)

    # Check for events.json
    events_path = get_scenario_file_path(scenario_name, 'events.json')
    if os.path.exists(events_path):
        run_event_file(events_path, event_args)

    # Ensure that time.sleep is properly handled even if wait is 0 or None
    if event_args.get('wait', None) is not None:
        time.sleep(event_args['wait'])

@cli.command()
@click.argument('file', type=click.Path(exists=True, readable=True))
@click.option('--source', default='synthetic-test', help='Source name for logs')
@click.option('--service', default='synthetic-events', help='Service name for logs')
@click.pass_context
def logs(ctx, file, source, service):
    """Sends log entries from a JSON or YAML file to Datadog.

    The file should contain a list of log objects or a single log object.
    Each log object is a dictionary that will be sent as a log entry.

    Args:
        ctx: The Click context object.
        file (str): Path to the JSON or YAML file containing log entries.
        source (str): Source name for the logs (e.g., 'my-app').
        service (str): Service name for the logs (e.g., 'backend').
    """
    dd_options = ctx.obj['dd_options']
    click.echo(f"Sending logs from file: {file}")
    
    # Get API key and site from context
    api_key = dd_options.get('api_key')
    if not api_key:
        click.echo("No Datadog API key found. Use --api-key or set DD_API_KEY environment variable.", err=True)
        ctx.exit(1)
    
    # Extract site from context
    site_url = dd_options.get('api_host', 'https://api.datadoghq.com')
    # Extract the domain part from the API host
    site = site_url.replace('https://', '').replace('http://', '')
    
    click.echo(f"Using Datadog site: {site}")
    click.echo(f"Using source: {source}")
    click.echo(f"Using service: {service}")
    
    # Set environment variables for send_log function
    os.environ['DATADOG_API_KEY'] = api_key
    os.environ['DD_SITE'] = site
    
    # Set up log arguments
    log_args = {
        "source": source,
        "service": service,
        "api_key": api_key,
        "site": site,
        "debug": ctx.obj['debug']  # Pass through debug flag
    }
    
    try:
        # Process logs
        try:
            with open(file, 'r') as f:
                data = json.load(f)
                
            if 'events' not in data or not isinstance(data['events'], list):
                click.echo(f"Error: Logs file {file} must contain an 'events' list.", err=True)
                ctx.exit(1)
                
            log_events = data['events']
            total_logs = len(log_events)
            
            if total_logs == 0:
                click.echo("No logs found in the file.")
                ctx.exit(0)
                
            click.echo(f"Found {total_logs} logs in file. Processing...")
            
            logs_sent_successfully = 0
            logs_failed_count = 0
            
            with click.progressbar(log_events, label='Sending logs') as progress_logs:
                for i, log_data in enumerate(progress_logs):
                    try:
                        # If log_data doesn't have a source, use the one from log_args
                        if "source" not in log_data:
                            log_data["source"] = source
                            
                        result = send_log(log_data, log_args)
                        
                        if result.get('status') == 'success':
                            logs_sent_successfully += 1
                        else:
                            logs_failed_count += 1
                            click.echo(f"Failed to send log {i+1}: {result}", err=True)
                        
                        # Sleep between events if interval is specified
                        if i < total_logs - 1 and ctx.obj['interval'] > 0:
                            time.sleep(ctx.obj['interval'])
                    except Exception as e:
                        logs_failed_count += 1
                        click.echo(f"Error sending log {i+1}: {e}", err=True)
            
            click.echo(f"\nSummary: Sent {logs_sent_successfully}/{total_logs} logs successfully. Failed: {logs_failed_count}")
            
        except json.JSONDecodeError as e:
            click.echo(f"Error: Invalid JSON in {file}. {str(e)}", err=True)
            ctx.exit(1)
    except Exception as e:
        click.echo(f"Error processing logs file: {e}", err=True)
        ctx.exit(1)

def _process_api_events_from_scenario(ctx, api_events_path, dd_options, scenario_interval):
    """Processes API events from a file within a scenario.

    Args:
        ctx: The Click context object.
        api_events_path (str): Path to the API events JSON file.
        dd_options (dict): Datadog API options.
        scenario_interval (float): Interval between sending events.
    """
    if not os.path.isfile(api_events_path):
        logger.debug(f"API events file not found at {api_events_path}, skipping API event processing.") # Changed to debug
        return

    click.echo(f"Processing API events from: {api_events_path}")
    logger.info(f"Processing API events from: {api_events_path}")
    try:
        events = load_events_from_file(api_events_path)
        click.echo(f"Loaded {len(events)} API events")
        logger.info(f"Loaded {len(events)} API events")

        results = process_batch(events, dd_options, scenario_interval)

        success_count = sum(1 for r in results if r is not None and 'errors' not in r and r.get('status') == 'ok')
        click.echo(f"API Events Summary: Sent {success_count}/{len(events)} events successfully.\n")
        logger.info(f"API Events Summary: Sent {success_count}/{len(events)} events successfully.")

    except Exception as e:
        click.echo(f"Error processing API events from {api_events_path}: {e}", err=True)
        logger.error(f"Error processing API events from {api_events_path}: {e}", exc_info=True)

def _process_email_events_from_scenario(ctx, email_events_path, sendgrid_api_key_option, email_recipient_override, scenario_interval, logs_only):
    """Processes email events from a file within a scenario.

    Args:
        ctx: The Click context object.
        email_events_path (str): Path to the email events JSON file.
        sendgrid_api_key_option (str): SendGrid API key from command option.
        email_recipient_override (str): Email recipient override from command option.
        scenario_interval (float): Interval between sending emails.
        logs_only (bool): True if only logs should be processed.

    Returns:
        bool: True if email events were skipped, False otherwise. This is to inform the main scenario function.
    """
    if not os.path.isfile(email_events_path):
        logger.debug(f"Email events file not found at {email_events_path}, skipping email event processing.")
        return True # Skipped because file not found

    click.echo(f"Processing email events from: {email_events_path}")
    logger.info(f"Processing email events from: {email_events_path}")

    current_sendgrid_api_key = sendgrid_api_key_option or os.environ.get('SENDGRID_API_KEY')

    if not current_sendgrid_api_key:
        click.echo("Error: SendGrid API key is required for email events. "
                   "Set it via --sendgrid-api-key option or SENDGRID_API_KEY environment variable.", err=True)
        logger.error("SendGrid API key missing for email events processing.")
        if not logs_only:
            ctx.exit(1)
        else:
            click.echo("Continuing with logs processing since --logs-only was specified.")
            return True # Skipped due to missing API key in non-logs-only mode
    
    if len(current_sendgrid_api_key) > 10:
        logger.info(f"Using SendGrid API key for scenario emails: {current_sendgrid_api_key[:4]}...{current_sendgrid_api_key[-4:]}")
    else:
        logger.warning("SendGrid API key for scenario emails appears very short or might be invalid.")

    try:
        with open(email_events_path, 'r') as f:
            email_scenario_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from email_events file {email_events_path}: {e}")
        click.echo(f"Error: Invalid JSON in {email_events_path}.", err=True)
        ctx.exit(1)
    except Exception as e:
        logger.error(f"Error reading email_events file {email_events_path}: {e}")
        click.echo(f"Error: Could not read email_events file {email_events_path}.", err=True)
        ctx.exit(1)

    emails_to_process = email_scenario_data.get('emails')
    if not isinstance(emails_to_process, list):
        logger.error(f"Email scenario file {email_events_path} must contain an 'emails' list.")
        click.echo(f"Error: Email scenario file {email_events_path} must contain an 'emails' list.", err=True)
        ctx.exit(1)

    email_delay_seconds = email_scenario_data.get('delay_seconds', scenario_interval)
    if not isinstance(email_delay_seconds, (int, float)) or email_delay_seconds < 0:
        logger.warning(f"Invalid 'delay_seconds' in email_events ({email_delay_seconds}), defaulting to {scenario_interval}s.")
        email_delay_seconds = scenario_interval

    total_emails = len(emails_to_process)
    emails_sent_successfully = 0
    emails_failed_count = 0

    if total_emails == 0:
        logger.info(f"No emails found in the {email_events_path} file.")
        click.echo(f"No emails to send in the {email_events_path} file.")
        return False # Not skipped, just no emails to send

    click.echo(f"Loaded {total_emails} email events to process from {email_events_path}.")
    with click.progressbar(emails_to_process, label='Sending scenario emails') as progress_emails:
        for i, email_config in enumerate(progress_emails):
            logger.info(f"Processing email {i + 1}/{total_emails} from scenario {email_events_path}...")

            template_data = email_config.get('template')
            if not isinstance(template_data, dict):
                logger.warning(f"Skipping email {i + 1} in scenario {email_events_path} due to missing or invalid 'template' object.")
                emails_failed_count += 1
                continue

            recipient = email_recipient_override or \
                        template_data.get('to_email') or \
                        os.environ.get('DD_EMAIL_ADDRESS')

            subject = template_data.get('subject')
            body = template_data.get('content')

            if not all([recipient, subject, body is not None]):
                logger.warning(f"Skipping email {i + 1} in scenario {email_events_path} due to missing recipient, subject, or content.")
                emails_failed_count += 1
                continue

            variables = email_config.get('variables', {})
            if isinstance(variables, dict) and variables:
                for key, value in variables.items():
                    placeholder = f"{{{{ {key} }}}}"
                    if isinstance(subject, str): subject = subject.replace(placeholder, str(value))
                    if isinstance(body, str): body = body.replace(placeholder, str(value))

            if _send_datadog_scenario_email(current_sendgrid_api_key, subject, body, recipient):
                emails_sent_successfully += 1
            else:
                emails_failed_count += 1

            if i < total_emails - 1 and email_delay_seconds > 0:
                logger.info(f"Waiting for {email_delay_seconds} seconds before next scenario email from {email_events_path}...")
                time.sleep(email_delay_seconds)

    click.echo(f"Email Events Summary ({email_events_path}): Sent {emails_sent_successfully}/{total_emails}. Failed: {emails_failed_count}.")
    logger.info(f"Email Events Summary ({email_events_path}): Sent {emails_sent_successfully}/{total_emails}. Failed: {emails_failed_count}.")
    return False # Processed, not skipped

if __name__ == '__main__':
    # Use Click CLI instead of argparse
    cli()
    
    # Original argparse implementation (commented out)
    """
    parser = argparse.ArgumentParser(description='Process events')
    parser.add_argument('--scenario', dest='scenarios', action='append',
                        help='scenario to run', required=True)
    parser.add_argument('--wait', dest='wait', type=int,
                        help='seconds to wait between scenarios', default=None)
    parser.add_argument('--source-type-name', dest='source_type_name', type=str,
                        help='source type name for events, if not already specified')
    args = parser.parse_args()

    event_args = {}
    if args.source_type_name:
        event_args['source_type_name'] = args.source_type_name

    init_options = {}
    logger = setup_logger()
    try:
        init_datadog(init_options)
        run_scenarios(args.scenarios, event_args, args.wait)
    except Exception as e:
        logger.error(f"Failed to run scenarios: {e}")
        raise
    """