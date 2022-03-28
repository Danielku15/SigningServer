# SigningServer
A simple server for code-signing binaries for internal infrastructure usage. 
If you work in a company with many teams it's sometimes hard to maintain code signing. Every team needs to sign their binaries
as part of their build process and therefore need the certificate installed on their build servers. This software solves this issue
by providing the code-signing as a service. You setup on a central signing server this software as a windows service and 
using the shipped client any other client can ask the central server to sign the files. 

## License / Credits

Unless stated otherwise the code of this project is licensed under:

> Copyright (c) 2020 Daniel Kuschny and Contributors
> Licensed under the MIT license.
> 
> [MIT license](LICENSE)

### SigningServer.Android
The code for Android signing is based on the apksig tool of the Android Open Source Project. 

> Copyright (c) 2016, The Android Open Source Project
> Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
> 
> [Apache License 2.0](SigningServer.Android/LICENSE).

It is ported for the Signing Server for proper integration with the certificates and signing mechanisms.

### SigningServer.MsSign
While the code in this area is owned by this project, credit goes over to @vcsjones
and his efforts behind https://github.com/vcsjones/AzureSignTool
He did an amazing job reverse engineering the new undocumented `SignerSignEx3` function which is the heart behind the signing mechanisms
provided by this library. 

Read more about his analysis here: https://vcsjones.dev/azure-signtool/