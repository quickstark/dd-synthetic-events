#!/bin/bash

# Builds and runs the Datadog events simulator
# Usage: ./run.sh [build options] [simulator options]
#
# Build options:
#   --rebuild         Delete existing image and rebuild it
#   --force-rebuild   Rebuild image from scratch with --no-cache
#
# Example commands:
#   ./run.sh --rebuild                                      # Just rebuild the image
#   ./run.sh test                                           # Send a test event
#   ./run.sh file examples/event_template.json              # Send events from a file
#   ./run.sh email --template examples/scenarios/scenario1/email_events.json  # Send email alerts
#   ./run.sh scenario --scenario-dir examples/scenarios/scenario1             # Run a complete scenario

IMAGE_NAME="datadog-events"

# Function to stop and remove containers using the image
stop_and_remove_containers() {
  CONTAINER_IDS=$(docker ps -a -q --filter ancestor="$IMAGE_NAME") # -a to include stopped containers that might block image removal
  if [ ! -z "$CONTAINER_IDS" ]; then
    echo "Stopping and removing existing containers based on $IMAGE_NAME..."
    docker stop $CONTAINER_IDS
    docker rm $CONTAINER_IDS
  else
    echo "No running or stopped containers found for $IMAGE_NAME."
  fi
}

# Check if the Docker image exists
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" != "" ]]; then
  # Check if rebuild flag is set
  if [[ "$1" == "--rebuild" ]]; then
    echo "Preparing to rebuild Docker image..."
    stop_and_remove_containers
    echo "Deleting existing Docker image..."
    docker rmi $IMAGE_NAME
    echo "Building Docker image..."
    docker build -t $IMAGE_NAME .
    shift # Consume the --rebuild flag
  elif [[ "$1" == "--force-rebuild" ]]; then
    echo "Preparing to force rebuild Docker image..."
    stop_and_remove_containers
    echo "Deleting existing Docker image (if any)..."
    docker rmi $IMAGE_NAME || true # Allow to fail if image not present
    echo "Force rebuilding Docker image (with --no-cache)..."
    docker build -t $IMAGE_NAME --no-cache .
    shift # Consume the --force-rebuild flag
  else
    # If first argument is not a rebuild flag, prompt user
    read -p "Existing $IMAGE_NAME image found. Rebuild it? [y/N] " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
      echo "Preparing to rebuild Docker image..."
      stop_and_remove_containers
      echo "Deleting existing Docker image..."
      docker rmi $IMAGE_NAME
      echo "Building Docker image..."
      docker build -t $IMAGE_NAME .
    fi
  fi
else
  # Image doesn't exist, build it
  echo "No existing $IMAGE_NAME image found. Building Docker image..."
  # It's good practice to ensure no containers are surprisingly using an image name that's about to be built,
  # though less likely if the image itself doesn't exist.
  stop_and_remove_containers
  docker build -t $IMAGE_NAME .
fi

# If the first argument was a rebuild flag, it would have been shifted.
# If it's still a rebuild flag here, it means only the flag was provided, and we should exit.
if [[ "$1" == "--rebuild" || "$1" == "--force-rebuild" ]]; then
  echo "Rebuild completed. Run again without the rebuild flag to execute a command."
  exit 0
fi

# Create data directory if it doesn't exist
mkdir -p $(pwd)/data

# Run the container with the provided arguments
# The '$@' will now correctly refer to the simulator options after build flags are shifted.
docker run -i \
  ${DD_API_KEY:+-e DD_API_KEY=$DD_API_KEY} \
  ${DD_APP_KEY:+-e DD_APP_KEY=$DD_APP_KEY} \
  ${DD_SITE:+-e DD_SITE=$DD_SITE} \
  ${SENDGRID_API_KEY:+-e SENDGRID_API_KEY=$SENDGRID_API_KEY} \
  ${DD_EMAIL_ADDRESS:+-e DD_EMAIL_ADDRESS=$DD_EMAIL_ADDRESS} \
  -v $(pwd):/app \
  -v $(pwd)/data:/app/data \
  $([ -t 0 ] && echo "-t") \
  $IMAGE_NAME "$@"