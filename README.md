# SeKey


## About
SeKey is a SSH Agent that allow users to authenticate to UNIX/Linux SSH servers using the Secure Enclave

## How it Works?
The Secure Enclave is a hardware-based key manager that’s isolated from the main processor to provide an extra layer of security. When you store a private key in the Secure Enclave, you never actually handle the key, making it difficult for the key to become compromised. Instead, you instruct the Secure Enclave to create the key, securely store it, and perform operations with it. You receive only the output of these operations, such as encrypted data or a cryptographic signature verification outcome.


### Limitations
* Only support MacBook Pro with the Touch Bar and Touch ID
* Can’t import preexisting key
* Stores only 256-bit elliptic curve private key


## Install

## Contribute
Members of the open-source community are encouraged to submit pull requests directly through GitHub.

