# Overview

Whilst doing some Purple Team exercises, we found that HTTP/S traffic from Empire was being blocked by a proxy. Cobalt Strike, for example, has DNS capabilities for staging its payloads and we wanted to have the same functionality in Empire.

# Usage

* Create the listener (dnstxt)
* Edit the "Host" field to be the DNS server that the victim uses (this will need to be changed to automatically extract the value from the victim machine in the future)
* Edit the fake domain to be a domain that you control (that is, you run the nameservers for that domain)
* Create the Python launcher and run it from your victim machine

# Design

* Listener
  * UDP server implemented using [scapy](http://www.secdev.org/projects/scapy/)
* Launcher
  * Encodes the initial stage 0 stager as a one line python script
  * Scapy can't be used, must use stdlib instead as it cannot be assumed that extra libraries are installed on the victim machine. Judicious usage of struct is required!
* Stager
  * Sets up the necessary crypto for downloading the full implant over DNS
* Agent
  * Actual implant which beacons back regularly to the Listener to receive tasking

The communication between the client (victim) and the server (attacker) is implemented in the following way:

* Data is sent from the server to the client
  * The client sends a DNS TXT request to the server. The hostname depends on which stage of the staging process the client & server are currently in
  * The server responds with a DNS TXT response indicating that data transfer can begin
  * The client sends another DNS TXT response for the first part of the data
  * In the case of large data transfers, like the stager and the agent, the data is compressed with zlib before sending
  * The data is encoded in base64 chunks of maximum length 168 (the length of a TXT record after all the headers and metadata have been added)
  * The data is then sent to the client as a DNS TXT response
  * When there is no more data left to send, the server responds to the client's TXT request with an NXDOMAIN ("No such name") response indicating the data transfer is over
* Data is sent from the client to the server
  * The client takes the payload to be sent to the server and encodes it into base32 chunks of length 64 (the maximum length for a DNS hostname label)
  * The client adds the hostname for the staging process to the labels and the domain which is used by the server
  * The client sends the request as a DNS A record request to the server
  * The server ACKs the data transfer with an A record response
  * When there is no more data left to send, the client sends an A record request for a specific hostname (the default is "smtp.") indicating that the data transfer is over.

# Requirements

* Scapy needs to be installed on the server, e.g., `sudo -H pip install scapy --upgrade`
* You need to have your own domain set up where the server is hosted, you need to be the authoratitive owner of the domain, that is, you need to be running the nameservers for the domain so that all DNS requests for the domain come to your server

# Protocol Breakdown

This is how the DNS staging process fits into the stages of the Empire staging process

* *Stage 1*: A record request received from launcher by listener with base32 encoded routing packet
  * Routing packet processed, compressed & encrypted stager is generated
  * A record response is sent back with a significant IP address 
* *Stage 2*: TXT record request is recv'd by listener
  * Response is sent from listener to launcher with compressed & encrypted stager via TXT record responses
  * Launcher decompresses and decrypts the stager then executes it
* *Stage 3*: Stager generates DH key and sends back to listener as multiple A record requests (base32 encoded hostname)
 * A record response is sent back with a significant IP address
* *Stage 4*: Listener receives TXT request from Stager
  * Stager receives TXT record response from Listener containing key and nonce
* *Stage 5*: Stager sends A record request to Listener with encrypted nonce and sysinfo
* *Stage 6*: Listener receives TXT record request from Stager
  * Stager receives compressed & encrypted Agent via TXT record responses, decompressed, decrypts and executes it

Tasking is performed in the following way

* Client sends a A record requests to server which contain a base32-encoded routing packet
* Server checks to see if tasking is available for the client
* If no tasking is available (standard Agent check-in), an IP address signifying a NOP operation is sent back to the client
* If tasking is available, an IP address signifying that tasking is available is sent back to the client
* The client then sends a TXT request to the server to retrieve the tasking information
* The server sends the tasking information back to the client via base64 encoded TXT responses as described above

# TODO

Lots :-)

* Launcher needs to extract DNS server from local machine and use that instead of hardcoded address
* PowerShell port
* Turn off all the debugging messages
* Handle multiple clients gracefully. This will probably involve simply rejecting clients whilst staging is ongoing and other clients sleeping until they get a slot (e.g., exponential backoff)
