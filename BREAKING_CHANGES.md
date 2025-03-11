# Breaking Changes

This document tries to list out breaking changes between versions 

## 2.x.x -> 3.0.0

* Certificates now can have a name attached for logging and reporting purposes via `CertificateName`, this should be set for all certificates.
* Previously certificates had only one username+password pair to be selected. For more fine-grained access control and auditing purposes, every certificate defines now the credentials in a `Credentials` list in the configuration.