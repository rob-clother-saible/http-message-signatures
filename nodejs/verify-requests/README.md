# Griffin API Request Verification - NodeJS Example

This example demonstrates how to verify incoming API requests from Griffin using the built-in `crypto` module of NodeJS.

## Prerequisites

- NodeJS 2.2 or later
- An API key from Griffin
- (To sign requests for the latest Griffin public key) An Ed25519 key pair registered with Griffin

## Generating an Ed25519 Key Pair

You can generate an Ed25519 key pair using the `openssl` command:

```bash
openssl genpkey -algorithm ed25519 -out private_key.pem -outpubkey public_key.pem
```

Follow our [documentation](https://docs.griffin.com/docs/guides/how-to-create-message-signatures/) for a step by step on registering your public key.

> [!IMPORTANT]  
> Store your private key securely and protect it from unauthorized access.
> Check out [Griffin's recommended security practices](https://docs.griffin.com/docs/introduction/api-security-overview/index.html#recommended-security-practices).

## Setup

1. Set the required environment variables:

```bash
export GRIFFIN_API_KEY="your_api_key"
export GRIFFIN_KEY_ID="your_key_id"
export GRIFFIN_PRIVATE_KEY_PATH="path/to/your/private_key.pem"
```

Or, write the values to the `.gitignore`d file `.env`, in the form

```
GRIFFIN_API_KEY=<your_api_key>
GRIFFIN_KEY_ID=<your_key_id>
GRIFFIN_PRIVATE_KEY_PATH=<path/to/your/private_key.pem>
```

If you don't set `GRIFFIN_PRIVATE_KEY_PATH`, the code will look for `private_key.pem` in the current directory.

2. Install the modules

```bash
npm install
```

This will:
1. Load your Ed25519 private key
2. Create and sign a request to Griffin's message signature verification endpoint
3. Print the response and request headers for debugging

## Troubleshooting

If you encounter errors:

- Check that your environment variables are set correctly
- Ensure your private key is a valid Ed25519 key in PEM format
- Verify that your key ID matches the one registered with Griffin
- Check the request headers in the debug output to ensure they're formatted correctly

## Additional Resources

- [Griffin's API Documentation](https://docs.griffin.com/docs/introduction/get-started-with-the-api)
- [Griffin's Message Signatures guide](https://docs.griffin.com/docs/guides/how-to-create-message-signatures)
- [Griffin's API Security guide](https://docs.griffin.com/docs/introduction/api-security-overview)

