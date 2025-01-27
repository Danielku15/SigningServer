# Features

This document gives a high level insight into the features of this software. At this point it gives a high level
insight about the functionalities without yet describing them in detail how to use and configure them. 

Consult the README.md, the configuration files and the command line help for more details or open an issue/discussion on GitHub.

https://github.com/Danielku15/SigningServer

## Centralized Code Signing Server

The server component of this software is a central point of contact for performing code signing in a distributed
corporate network. Using the Signing Client or the Standalone Client together with the server a wide list of file
formats can be signed. 

* Windows Executables (.exe, .dll)
* Windows Drivers (.sys, .cat)
* Windows Installer Packages (.msi)
* Cabinet Files (.cab)
* PowerShell Scripts (.ps1, *.psm1)
* Raw Signature Blobs (e.g. for manual verification via OpenSSL)
* Android APKs (.apk, Signature Schemes v1, v2, v3, v4)
* Android Bundles (.aab)
* Java Archives (.jar)
* NuGet Packages (.nupkg)
* OCI Containers by using cosign attach (sign raw signature blobs)
* Universal Windows Platform (UWP) Apps (.appx, .appxbundle, .eappx, .eappxbundle, .msix)

Clients can customize the hash algorithm used for signing: 

* SHA-1 (deprecated)
* SHA-256 (default)
* SHA-384
* SHA-512

### Timestamping

When signing files, also a timestamping is done automatically using the configured timestamping server.

For SHA-1 signatures, a special timestamping server can be configured as newer ones might reject old SHA-1 signatures.

### Basic Landing Page

When opening the URL of the signing server in the browser the users are presented a simple landing page.
Admins can configure some basics like the name of the service and a small description text.
Additionally, some links to a support portal and knowledge base can be added. 

### Logging

The server logs all signing requests and responses in textual format into log files. 

This can help in troubleshooting scenarios. The logging is configured using the NLog section in the asppsettings.json:

* https://nlog-project.org/config/
* https://github.com/NLog/NLog/wiki/Configuration-file

### Usage Tracking

Since version 3.x the server can track usage of the server by logging the user and certificate used. 
It does not archive every request individually but rather aggregates statistics like: 

* How many requests were made by a user
* How many signatures were produced
* How many signatures were skipped (e.g. due to files already signed).

The statistics are tracked in daily JSON files stored in the `audit` folder.

A Excel File with the whole usage statistics can be downloaded from the web interface.

### Supported Certficate Stores

#### Windows Certificate Store

Use certificates from the Windows Certificate store for signing. When using hardware stored certificates (HSMs, USB Dongles etc.)
it might be required to unlock the token via PIN, this is handled by the software. 

#### Azure KeyVault

Use certificates stored in Azure KeyVault for signing. Simply configure the KeyVault, Certificate and access credentials to use them.

## (Thin) Signing Client

The default signing client will upload the whole binary to the server for signing. This allows signing of any file format on any platform
at the cost of uploading the whole file to the server.

Overall the client can:

* Perform code signing of files given individual files or directories as input. 
* Perform signing of any file as binary blob (hashing the file as-is and creating a signature) for manual usage. 
* Downloading of the certificate chain for verification purposes (only public key).

## Standalone Signing Client (experimental)

The standalone signing client performs most of the code signing aspects locally. It only contacts the remote server for 
computing the digital signature of a locally hashed file. This allows to sign files without uploading the whole file to the server.

The benefit is that not all files have to be fully uploaded saving bandwidth and increasing signing speed.
The drawback is that signing of some formats might not be available on all platforms. Windows Binary signing relies on native Windows APIs not available on Linux or MacOS. 
Also Timestamping has to happen locally which increases the complexity.

* Perform code signing of files given individual files or directories as input.
* Perform signing of any file as binary blob (hashing the file as-is and creating a signature) for manual usage.
* Downloading of the certificate chain for verification purposes (only public key).

Unlike the thin client this client has not been battle-tested in production and is therefore considered experimental. 


