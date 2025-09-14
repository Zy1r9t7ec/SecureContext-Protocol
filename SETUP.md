# SecureContext Protocol - Setup Guide

This guide will help you set up and run the SecureContext Protocol Authentication Proxy locally.

## Prerequisites

- Python 3.10 or higher
- A Google Cloud Platform account (for Google OAuth)
- A Microsoft Azure account (for Microsoft OAuth)

## Step 1: Install Dependencies

```bash
# Install Python dependencies
pip install -r requirements.txt
```

## Step 2: Set Up OAuth Applications

### Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API and Gmail API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Choose "Web application"
6. Add authorized redirect URIs:
   - `http://localhost:5000/oauth/google/callback`
   - `http://127.0.0.1:5000/oauth/google/callback`
7. Copy the Client ID and Client Secret

### Microsoft OAuth Setup

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" → "App registrations"
3. Click "New registration"
4. Set the redirect URI to: `http://localhost:5000/oauth/microsoft/callback`
5. After creation, go to "Certificates & secrets" → "New client secret"
6. Copy the Application (client) ID and the client secret value

## Step 3: Configure Environment Variables

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit the `.env` file with your OAuth credentials:
   ```bash
   # Google OAuth 2.0 Configuration
   GOOGLE_CLIENT_ID=your_actual_google_client_id
   GOOGLE_CLIENT_SECRET=your_actual_google_client_secret

   # Microsoft OAuth 2.0 Configuration
   MICROSOFT_CLIENT_ID=your_actual_microsoft_client_id
   MICROSOFT_CLIENT_SECRET=your_actual_microsoft_client_secret

   # Flask Configuration
   FLASK_SECRET_KEY=your_random_secret_key_here
   ```

3. Generate a secure Flask secret key:
   ```python
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

## Step 4: Run the Application

```bash
# Run the application
python run.py
```

The server will start at `http://localhost:5000`

## Step 5: Test the OAuth Flows

1. Open your browser and go to `http://localhost:5000`
2. Click "Connect Google Account" or "Connect Microsoft Account"
3. Complete the OAuth authorization flow
4. You should see a success message with a session ID

## Step 6: Test Token Retrieval

Use the verification script to test token retrieval:

```bash
# Replace SESSION_ID with the actual session ID from step 5
python verify_tokens.py SESSION_ID
```

Or use curl:

```bash
curl http://localhost:5000/api/tokens/SESSION_ID
```

## Troubleshooting

### Common Issues

1. **"Configuration Error: Missing required environment variables"**
   - Make sure your `.env` file exists and contains all required variables
   - Check that there are no typos in variable names

2. **OAuth redirect URI mismatch**
   - Ensure your OAuth app redirect URIs exactly match:
     - Google: `http://localhost:5000/oauth/google/callback`
     - Microsoft: `http://localhost:5000/oauth/microsoft/callback`

3. **"Invalid client" errors**
   - Double-check your client IDs and secrets
   - Make sure you're using the correct credentials for each provider

4. **Port already in use**
   - Change the port in your `.env` file:
     ```
     FLASK_PORT=5001
     ```

### Debug Mode

To enable debug mode for more detailed error messages:

```bash
# Add to your .env file
FLASK_DEBUG=true
```

### Logs

The application logs detailed information about OAuth flows. Check the console output for debugging information.

## Security Notes

- This is a development setup using HTTP. For production, use HTTPS
- Tokens are stored in memory and cleared when the application restarts
- Never commit your `.env` file to version control
- Use strong, unique secret keys for production deployments

## Next Steps

Once you have the basic setup working:

1. Test with different OAuth scopes
2. Integrate with your AI agent frameworks
3. Explore the extensible provider architecture
4. Consider production deployment options

## Support

If you encounter issues:

1. Check the console logs for detailed error messages
2. Verify your OAuth app configurations
3. Test with curl to isolate UI vs API issues
4. Review the troubleshooting section above