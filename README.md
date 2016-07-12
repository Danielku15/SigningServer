# SigningServer
A simple server for code-signing binaries for internal infrastructure usage. 
If you work in a company with many teams it's sometimes hard to maintain code signing. Every team needs to sign their binaries
as part of their build process and therefore need the certificate installed on their build servers. This software solves this issue
by providing the code-signing as a service. You setup on a central signing server this software as a windows service and 
using the shipped client any other client can ask the central server to sign the files. 

