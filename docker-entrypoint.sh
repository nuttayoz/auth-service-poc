#!/bin/sh
set -eu

echo "Running Prisma migrations..."
bunx prisma migrate deploy

echo "Starting auth-service..."
exec bun dist/main.js
