FROM python:3.9-slim

WORKDIR /app

# Set environment variable placeholders - these will be overridden at runtime
ENV DD_API_KEY="your_api_key_here"
ENV DD_APP_KEY=""
# Default to Datadog US site
ENV DD_SITE="api.datadoghq.com" 
# SendGrid API key for email feature
ENV SENDGRID_API_KEY=""
# Default Datadog email address for email-to-event conversion
ENV DD_EMAIL_ADDRESS="event-l3iss4to@dtdg.co"
# Default Sender email address for SendGrid
ENV SENDER_EMAIL_ADDRESS="dirk@quickstark.com"

# Create a label with usage instructions
LABEL org.opencontainers.image.description="Datadog Event Simulator - Set DD_API_KEY when running this container"
LABEL org.opencontainers.image.usage="docker run -e DD_API_KEY=your_api_key_here datadog-events test"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Make script executable
RUN chmod +x /app/src/simulator.py

ENTRYPOINT ["python", "src/simulator.py"]