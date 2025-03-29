# OutlineWebhook

This project is modified from [Frando's Outline Webhook example](https://gist.github.com/Frando/aa561ca7e6c72ab64b5d17df911c0b1f). It provides a simple webhook server built with Deno.

## Prerequisites

- A keycloak client configured in your realm with service account permissions to access keycloak user groups
- A webhook configured in outline (note that the container expects the webhook to come to /webhook)

## Running the Application

1. Build the Docker image:
   ```bash
   docker build -t outline-webhook .
   ```
2. Run the Docker container:
   ```bash
   docker run -p 8000:8000 outline-webhook
   ```
3. The server will be accessible on port `8000`.

## Environment Variables

- `DENO_ENV`: Set to `production` by default in the Dockerfile.
- `WEBHOOK_SECRET`: Your Outline webhook secret.
- `OUTLINE_ENDPOINT`: The API endpoint of your Outline instance (e.g., `https://your-outline-instance.com/api`).
- `OUTLINE_API_TOKEN`: Your Outline API token.
- `KEYCLOAK_ENDPOINT`: The endpoint of your Keycloak instance (e.g., `https://your-keycloak-instance.com`).
- `KEYCLOAK_REALM`: Your Keycloak realm.
- `KEYCLOAK_CLIENT_ID`: Your Keycloak client ID.
- `KEYCLOAK_CLIENT_SECRET`: Your Keycloak client secret.

## Credits

This project is inspired by and based on [Frando's Outline Webhook example](https://gist.github.com/Frando/aa561ca7e6c72ab64b5d17df911c0b1f). Special thanks to Frando for the original implementation.