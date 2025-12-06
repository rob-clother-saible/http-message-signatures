# Griffin API Request Signing - NodeJS Example

This example demonstrates how to sign API requests to Griffin using the built-in `crypto` module of NodeJS.

NodeJS has the benefit of being a newer language. Older languages, such as C# and Java, could not ship crypto functionality as standard, due to US export restrictions.

## Prerequisites

- NodeJS 2.2 or later
- An API key from Griffin
- An Ed25519 key pair registered with Griffin

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

## Running the Example

To run the example:

```bash
node main.js <GET|POST|PUT|PATCH|DELETE> <url_path_or_filename>
```

e.g.

```bash
node main.js GET /v0/index
```

To run a POST, PUT, PATCH or DELETE command, add the endpoint and the body of the request to a JSON file: e.g.

```json
{
  "endpoint": "/v0/legal-persons/{legal-person-id}",
  "body": {
    "display-name": "{display-name}"
  }
}```

Save this text to a file (e.g. `update_legal_person.json`) in the `.gitignore`d `commands` folder, and execute the command by referencing the filename: e.g.

```bash
node main.js POST update_legal_person.json
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

