#!/usr/bin/env bash

: > banned_users.txt

echo "Building and starting Collapse IRC Server with Docker Compose..."

docker compose up --build -d

echo "Compose started. Use 'docker compose logs -f' to follow logs and 'docker compose down' to stop." 
