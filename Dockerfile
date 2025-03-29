# Use the official Deno Alpine image
FROM denoland/deno:alpine

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . .

# Expose the port the application will run on
EXPOSE 8000

# Set environment variables
ENV DENO_ENV=production

# Run the application
CMD ["run", "--allow-net", "--allow-env", "--allow-read", "server.ts"]
