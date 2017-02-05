# Overview

Whilst doing some Purple Team exercises, we found that HTTP/S traffic from Empire was being blocked by a proxy. Cobalt Strike, for example, has DNS capabilities for staging its payloads and we wanted to have the same functionality in Empire.

# Design

* Listener
  * UDP server implemented using scapy
* Launcher
  * Encodes the initial stage 0 stager as a one line python script
  * Can’t use scapy, must use stdlib instead as it cannot be assumed that extra libraries are installed on the victim machine
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
