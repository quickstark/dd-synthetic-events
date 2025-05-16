#!/usr/bin/env python3

import os
import json
import time # For delay
import click
import sendgrid
from sendgrid.helpers.mail import Mail
import logging

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Global Configuration ---
# Define Sender Email Address (from environment or default)
SENDER_EMAIL_FALLBACK = "dirk@quickstark.com"
SENDER_EMAIL = os.environ.get('SENDER_EMAIL_ADDRESS', SENDER_EMAIL_FALLBACK)

# Note: SENDGRID_API_KEY will be fetched from env or CLI option within the command

def _send_single_email(sendgrid_api_key: str, subject: str, body: str, recipient_email: str) -> bool:
    """Sends a single email using SendGrid.

    Args:
        sendgrid_api_key: The SendGrid API key.
        subject: The subject of the email.
        body: The plain text content of the email.
        recipient_email: The email address of the recipient.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    if not sendgrid_api_key:
        logger.error("SendGrid API key not provided, cannot send email.")
        return False
    
    if not recipient_email:
        logger.error("Recipient email not provided, cannot send email.")
        return False

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
            return True
        else:
            logger.error(f"SendGrid returned non-successful status code: {status_code} for {recipient_email}. Body: {response.body}")
            return False
        
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email} via SendGrid: {str(e)}", exc_info=True)
        return False

def _process_and_send_email(email_config: dict, api_key: str, email_index: int, total_emails: int) -> bool:
    """Processes a single email configuration and sends the email.

    Args:
        email_config: Dictionary containing the email's template and variables.
        api_key: SendGrid API key.
        email_index: The index of the current email being processed.
        total_emails: The total number of emails to be processed.

    Returns:
        True if the email was sent successfully, False otherwise.
    """
    logger.info(f"Processing email {email_index + 1}/{total_emails}...")

    template_data = email_config.get('template')
    if not isinstance(template_data, dict):
        logger.warning(f"Skipping email {email_index + 1} due to missing or invalid 'template' object.")
        return False

    recipient = template_data.get('to_email')
    subject = template_data.get('subject')
    body = template_data.get('content')

    if not all([recipient, subject, body is not None]):  # body can be an empty string
        logger.warning(f"Skipping email {email_index + 1} due to missing 'to_email', 'subject', or 'content' in template data.")
        return False

    # Basic variable processing
    variables = email_config.get('variables', {})
    if isinstance(variables, dict) and variables:
        for key, value in variables.items():
            placeholder = f"{{{{ {key} }}}}"  # Matches {{ key }}
            if isinstance(subject, str):
                subject = subject.replace(placeholder, str(value))
            if isinstance(body, str):
                body = body.replace(placeholder, str(value))

    return _send_single_email(api_key, subject, body, recipient)

@click.command()
@click.option('--file-path', 
              required=True, 
              type=click.Path(exists=True, readable=True, dir_okay=False), 
              help='Path to the JSON file containing email scenario definitions (e.g., email_events.json).')
@click.option('--api-key', 
              envvar='SENDGRID_API_KEY', 
              help='SendGrid API key. Can also be set via SENDGRID_API_KEY environment variable.')
def send_scenario(file_path: str, api_key: str):
    """Reads email definitions from a JSON scenario file and sends them using SendGrid.

    The JSON file should have an "emails" key containing a list of objects.
    Each object should have a "template" key, which in turn contains:
    - "to_email": Recipient's email address.
    - "subject": Email subject.
    - "content": Email body (plain text).
    
    An optional "delay_seconds" key can be present at the root of the JSON
    to specify a delay between sending emails.

    Args:
        file_path: Path to the JSON file containing email scenario definitions.
        api_key: SendGrid API key.
    
    Example `email_events.json` structure:
    ```json
    {
      "emails": [
        {
          "template": {
            "to_email": "recipient1@example.com",
            "subject": "Subject for email 1",
            "content": "Body for email 1."
          },
          "variables": {} // Optional, for placeholder replacement
        }
      ],
      "delay_seconds": 0
    }
    ```
    """
    logger.info(f"Starting email scenario from file: {file_path}")
    logger.info(f"Using sender email: {SENDER_EMAIL}")

    if not api_key:
        logger.error("SendGrid API key is missing. Please provide it via --api-key option or SENDGRID_API_KEY environment variable.")
        print("Error: SendGrid API key is missing.")
        return

    if len(api_key) > 10:
        logger.info(f"Using SendGrid API key: {api_key[:4]}...{api_key[-4:]}")
    else:
        logger.warning("SendGrid API key appears very short or might be invalid.")


    try:
        with open(file_path, 'r') as f:
            scenario_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from file {file_path}: {e}")
        print(f"Error: Invalid JSON in {file_path}.")
        return
    except Exception as e:
        logger.error(f"Error reading scenario file {file_path}: {e}")
        print(f"Error: Could not read scenario file {file_path}.")
        return

    emails_to_process = scenario_data.get('emails')
    if not isinstance(emails_to_process, list):
        logger.error(f"Scenario file {file_path} must contain an 'emails' list.")
        print(f"Error: Scenario file {file_path} must contain an 'emails' list.")
        return

    delay_seconds = scenario_data.get('delay_seconds', 0)
    if not isinstance(delay_seconds, (int, float)) or delay_seconds < 0:
        logger.warning(f"Invalid 'delay_seconds' value ({delay_seconds}), defaulting to 0.")
        delay_seconds = 0
    
    total_emails = len(emails_to_process)
    emails_sent_successfully = 0
    emails_failed = 0

    if total_emails == 0:
        logger.info("No emails found in the scenario file.")
        print("No emails to send in the scenario file.")
        return

    for i, email_config in enumerate(emails_to_process):
        if _process_and_send_email(email_config, api_key, i, total_emails):
            emails_sent_successfully += 1
        else:
            emails_failed += 1

        if i < total_emails - 1 and delay_seconds > 0:
            logger.info(f"Waiting for {delay_seconds} seconds before next email...")
            time.sleep(delay_seconds)

    logger.info("--- Scenario Summary ---")
    logger.info(f"Total emails defined: {total_emails}")
    logger.info(f"Successfully sent: {emails_sent_successfully}")
    logger.info(f"Failed to send: {emails_failed}")
    print(f"Scenario completed. Sent: {emails_sent_successfully}/{total_emails}. Failed: {emails_failed}.")

if __name__ == '__main__':
    send_scenario()