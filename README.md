# OpenID Connect service provider

## Description

This repository contains a NestJS server configured as an OpenID Connect service provider. The server has authentication and logout endpoints and recognize returning users in compliance with the OpenID Connect standard.

Once the server is running, you can access the client in your browser by navigating to https://fs.tpommellet.docker.dev-franceconnect.fr

## Limitations and Design Choices

To focus on core functionalities, the following design decisions and simplifications have been made:

- <b>Client Interface</b>: The client is served statically by the NestJS server, leading to the FranceConnect authentication response being directed to a server endpoint. This necessitates handling state and nonce internally within the authentication service due to cross-domain cookie access restrictions. Optimally, a client-side redirect would enable secure storage and retrieval of these values via cookies.
- <b>User Database</b>: The current user database is represented as a simple list within the user service. This basic setup does not perform checks for existing users before new user creation nor does it update local user information with data received from FranceConnect. A more robust implementation would involve persistent storage and mechanisms to check and synchronize user data.

## Environment Configuration

Create a .env file in the root of the project with the following keys and values.</br>
NB: replace CLIENT_SECRET with the client secret I've received by SMS

```plaintext
# .env file

JWT_SECRET='tanguypommellet'
PROTECTED_ENDPOINT='https://fs.tpommellet.docker.dev-franceconnect.fr/protected'
FC_CONFIG_URL='https://fcp-low.integ01.dev-franceconnect.fr/api/v2/.well-known/openid-configuration'
LOGIN_REDIRECT_URI='https://fs.tpommellet.docker.dev-franceconnect.fr/api/login-callback'
POST_LOGOUT_REDIRECT_URI='https://fs.tpommellet.docker.dev-franceconnect.fr/api/logout-callback'
CLIENT_ID='51c101172767dfe77fcfa3a67f8b0e6039fbd5c14442ef8e175e21de94dccb2c'
CLIENT_SECRET=
```

## Installation using dockers (preferred)

Before running the application, ensure you have the following prerequisites installed:

- Docker (Follow the Docker installation guide here: https://docs.docker.com/get-docker/)

### Building the Docker Image

Build the Docker image by running:

```bash
$ docker build -t franceconnect-app .
```

### Running the App with Docker

To run the app in a Docker container, execute:

```bash
$ docker run -p 443:443 franceconnect-app
```

## Installation without dockers

Before running the application, ensure you have the following prerequisites installed:

- Node.js version 18.13
- mkcert to run this application with HTTPS locally.

### Setting Up SSL for Local Development with mkcert

This application is configured to run over HTTPS locally. To set up SSL for local development, follow these steps:

1. Install mkcert (follow the installation instructions for mkcert here: https://github.com/FiloSottile/mkcert)

2. Run `mkcert -install` to set up a local CA.

3. Navigate to this project directory and create a certs directory if it doesn't exist:

```bash
$ mkdir -p certs && cd certs
```

4. Generate SSL certificates for your local development domain:

```bash
$ mkcert fs.tpommellet.docker.dev-franceconnect.fr
```

This will generate two files: `fs.tpommellet.docker.dev-franceconnect.fr.pem` and `fs.tpommellet.docker.dev-franceconnect.fr-key.pem`. Ensure these files are located in the `./certs` directory within the project.

### Dependencies installation

Install all dependencies by running:

```bash
$ npm install
```

### Running the App

To run the app locally with HTTPS:

```bash
# development mode
$ npm run start

# watch mode
$ npm run start:dev
```

By default, the application will start on port 443. Ensure this port is available or change the port in your environment configuration.

### Tests

Run your tests with the following commands:

```bash
# unit tests
$ npm run test

# end to end tests
$ npm run test:e2e

# test coverage
$ npm run test:cov
```

## License

Nest is MIT licensed.
