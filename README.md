# Zero Knowledge Proof Authentication
This is an example implementation of the Chaum-Pedersen Zero Knowledge Proof protocol in Rust.

## Table of Contents
- [Parameters](#parameters)
- [Launch Postgres database in docker](#launch-postgres-database-in-docker)
- [Build the project](#build-the-project)
- [Run in separate terminals](#run-in-separate-terminals)
- [Screenshot of Usage](#screenshot-of-usage)
- [Usage](#usage)
- [Quick Links](#quick-links)

## Screenshot of Usage
[screenshot here]

## Usage
- Build in docker `make build`
- Run the server in docker `make run-server`
- Start the client container `make run-client`
- Run command in client docker container `make client-register` or `make client-login`

## Quick Links
- [Chaum-Pedersen Protocol](https://en.wikipedia.org/wiki/Chaum%E2%80%93Pedersen_protocol)
- [Schnorr Group](https://en.wikipedia.org/wiki/Schnorr_group)