# bind-restapi

A quick and simple RESTful API to BIND, written in Python/Tornado. Provides the ability to add/remove TXT entries within an existing BIND DNS architecture.

## Architecture

The architecture of the application is overall very simple. A single CentOS
Linux host or container with network access to your DNS servers is all that is
required to host the application. A single Python file defines the logic for a
Tornado web application, which accepts incoming HTTPS requests on a
(configurable) TCP port. The parameters and HTTP verb of the request are
translated into an `nsupdate` script for creating/deleting DNS records, which
is executed in a subprocess. The service is executed and managed via `systemd`.

## Security 

All `nsupdate` commands are authenticated using a pre-shared, symmetric DNNSEC
key. The web application can only make updates to DNS zones in which the key is
authorized to make updates. 

The API itself is password protected by way of an API Key using a custom
`X-Api-Key` HTTP header. Only clients with the correct password passed in via
the `X-Api-Key` header can make requests against the API. 

Finally, SSL certificates are used to encrypt traffic passing between the
client and server. This prevents any header information (like the API key) from
being transmitted in clear text. 

## Installation

 1. Clone this repository into a location of your choosing
 2. Modify the `bind-api.conf` file to suit your needs 
 3. Run the installation script to install dependencies, stage the config files
 and code file, and enable and start the systemd service: `chmod u+x install.sh
 && ./install.sh`

 The installation script is a bit primitive, and has paths for the various
 configuration files and code files hardcoded. Check the installation script
 for the paths of all important files, and modify the script to suit your needs
 if necessary. If the path of the code files and configuration files are
 changed in the installation script, they must also be changed in the systemd
 unit file and Python code file accordingly. Documentation of configurable
 parameters is below:

| **Parameter**        | **Type**            | **Description**                                                                       |
|------------------|-----------------|-----------------------------------------------------------------------------------|
| nameserver       | List of strings | List of IP addresses of nameservers to send updates to                            |
| get_nameservers  | List of strings | List of hardcoded nameserver names for faster GET response                        |
| address          | string          | IP address to listen for incoming requests on                                     |
| port             | integer         | TCP port to listen for incoming requests on                                       |
| logging          | string          | Logging level. One of "info", "debug", "warn", "error".                           |
| logfile          | string          | Absolute path to log file for server.                                             |
| ttl              | integer         | Default TTL for all records created by the server                                 |
| sig_key          | string          | Absolute path to DNSSEC key file                                                  |
| secret           | string          | Password for the server. Client place this in the `X-Api-Key` header              |
| nsupdate_command | string          | Absolute path to nsupdate binary, if not already on $PATH environment variable    |
| cert_path        | string          | Absolute path to SSL certificate used by API server                               |
| cert_key_path    | string          | Absolute path to private key of the SSL certificate used by the API server        |

**WARNING:** The configuration file is an executable Python file that is
imported by the main application code. Manage permissions on this file
according to prevent execution of malicious code.

## API

See the [Swagger Documentation](https://klar.github.io/bind-restapi/) for the API. For an interactive
version with automated generation of example CURL commands, paste the contents
of the swagger.yml file into the [Online Swagger
Editor](https://editor.swagger.io/).
