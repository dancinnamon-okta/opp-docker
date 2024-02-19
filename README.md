# opp-docker
This repository contains an easy way to run Okta's on-premise provisioning agent within a docker container on your own machine.  Included are the following containers:
* A container running the on-premise provisioning agent. This also includes a sharable volume to place CSV files for use with Okta's CSV directory functionality.
* A container running a pre-compiled version of the Okta on-premise provisioning SDK sample. That sample uses the Okta SDK to host a SCIM service, which uses local .json files as it's data store. This can be used to show a bi-directional on-premise provisioning connection.


## How to install

> **Note**: The install instructions were tested on an M1 Mac.  They should work on any mac, but will require some minor adjustment for windows (openssl tools are used in the build on these images).

> **Pre-requisites**
> * Docker installed on your machine
> * OpenSSL (already installed on Mac/Linux)

### Step 1 - Download this repository
```console
git clone https://github.com/dancinnamon-okta/opp-docker.git
```

### Step 2 - Copy and fill in the .env file
```console
cp .env.example .env
```
Follow the instructions in the file to fill in the 5 variables needed.

### Step 3 - Build the images
```console
bash build.sh
```
During the build process, you'll be presented with a login URL (OAuth2 device-code flow) to your chosen Okta tenant. Follow the instructions at the prompt to authorize the OPP agent that is being built.

### Step 4 - Run!
```console
docker compose up
```
This command will run the built images, and you're all set to show off Okta on-premise provisioning!
In the Okta console in the dashboard->agents menu you can see that the OPP agent is connected.

To validate the operation of the LDAP SCIM gateway, visit the following URLs:
https://localhost:8881/Users
http://localhost:18080

You may also execute ldap commands, such as ldapsearch, from the commandline against ldap://localhost:1389.

In Okta, when configuring OPP for a given application, use the following configuration:

Base URL: https://scimgateway:8881

Authentication: Basic

Username: Value set in .env file

Password: Value set in .env file

Unique field: userName


The following capabilities are supported against LDAP:
* Create, Update, Disable Users
    * Attributes Supported: FirstName, LastName, Email, Mobile

* Group Push
* Password Push
