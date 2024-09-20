#!/bin/bash

# Function to run tests
run_tests() {
    # Load environment variables from .env file
    if [ -f .env ]; then
        export $(grep -v '^#' .env | xargs)
    fi

    # Check Node.js version
    echo "Node.js version:"
    node --version

    # Check npm version
    echo "npm version:"
    npm --version

    # Check TypeScript version
    echo "TypeScript version:"
    npx tsc --version

    # Check Mocha version
    echo "Mocha version:"
    npx mocha --version

    # Check if KEEPER_CONFIG is set
    if [ -z "$KEEPER_CONFIG" ]; then
        echo "Error: KEEPER_CONFIG is not set in .env file."
        exit 1
    fi

    # Run the tests
    npm test
}

# Check if we're running inside a Docker container
if [ -f /.dockerenv ]; then
    # We're inside the Docker container, just run the tests
    run_tests
else
    # We're on the host, so we need to build and run the Docker container

    # Check if Docker is installed
    if ! command -v docker &> /dev/null
    then
        echo "Docker is not installed. Please install Docker and try again."
        exit 1
    fi

    # Build the Docker image
    echo "Building Docker image..."
    DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -t keeper-secrets-test .

    # Run the tests in the Docker container
    echo "Running tests in Docker container..."
    DOCKER_DEFAULT_PLATFORM=linux/amd64 docker run --rm -v $(pwd)/.env:/app/.env keeper-secrets-test

    # Capture the exit code of the Docker run command
    EXIT_CODE=$?

    # Exit with the same code as the Docker container
    exit $EXIT_CODE
fi