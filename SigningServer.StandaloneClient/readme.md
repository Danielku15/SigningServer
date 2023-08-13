# SigningServer Client

This is a .net Tool for the client part of the Software [SigningServer](https://github.com/Danielku15/SigningServer)
a service for centralizing code signing workloads in corporate environments. This client can reach out to a server counterpart
to perform code signing operations on a range of supported file formats.

You can read more about consuming .net Tools [here](https://learn.microsoft.com/en-us/dotnet/core/tools/global-tools).

### Configuration

The client can be either configured through a configuration file or a range of command line parameters. Call
the tool with `--help` to learn more about all the available options.

### Client Exit Codes

The client provides exit codes for each error scenario:

* `1` - Unexpected Error, Details should be in the log file.
* `2` - File not found.
* `3` - File is already signed (can be silenced through `IgnoreExistingSignatures`)
* `4` - Unsupported file format (can be silenced through `IgnoreUnsupportedFiles`)
* `5` - Invalid username or password provided
* `6` - Invalid configuration, check the json file for errors
* `7` - An error when communicating with the server occured
* `8` - Security Negotiation Failed
