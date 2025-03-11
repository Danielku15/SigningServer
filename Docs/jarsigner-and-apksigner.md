# `jarsigner` and `apksigner` 
This document tries to document a bit the specifics of the signing of Android and Java applications. 

There are two file formats and signing tools are used normally to sign such applications: 

* `.apk` Represents an Android application package which can be installed. They can be signed with `apksigner` from the Android SDK.
* `.aab` Represents an Android Bundle but it is treated special by Android. It is not considered the final APK sent to the Apps via the store. Google dynamically delivers the files required from the app to the client. Therefore it does not have a full APK signing but Google does the APK level signing when delivering them to the user. AAB files are signed just like Jars which is equal to a "v1 signature scheme". Officially `apksigner` cannot be used to sign AAB files, the normal JDK `jarsigner` is used. 
* `.jar` are simple Java applications (or libraries) which also support signing. The JDK ships a `jarsigner` tool to do this signing.

## ApkSigner Behavior 

Documentation about APK signing is documented here: https://source.android.com/docs/security/features/apksigning

The following points describe how `apksigner` behaves for scenarios where no explicit settings from outside are supplied and what manual options are available. 

* `apksigner` claims to use uses the AndroidManifest.xml embedded in the APK to load the minimum SDK version for the app. But actually internally it rather applies all signature schemes to the APK but unsupported ones are simply not verified. The `apksigner` has no logic to disable/enable signature schemes dynamically based on the SDK version. 
* The v1 signature scheme digest algorithm is automatically determined based on the min-sdk-version and the certificate used:
    * RSA certificates and min-sdk-version < 18: SHA-1
    * RSA certificates and min-sdk-version >= 18: SHA-256
    * DSA certificates and min-sdk-version < 21: SHA-1
    * DSA certificates and min-sdk-version >= 21: SHA-256
    * ECDSA certificates and min-sdk-version < 18: Leads to an error as ECDSA is only supported with SDK >= 18
    * ECDSA certificates and min-sdk-version >= 18: SHA-256
    * If multiple certificates are used, SHA-256 wins over SHA-1
* The v2 signature scheme digest algorithm is automatically determined based on the certificate used:
    * RSA certificates with modulo bits <= 3072 bits: SHA-256
    * RSA certificates with modulo > 3072 bits: SHA-512
    * DSA certificates: SHA-256
    * ECDSA certificates with key size <= 256 bits: SHA-256
    * ECDSA certificates with key size > 256 bits: SHA-512
* The v3 signature scheme digest algorithm is automatically determined based on the certificate used:
    * RSA certificates with modulo bits <= 3072 bits: SHA-256
    * RSA certificates with modulo > 3072 bits: SHA-512
    * DSA certificates: SHA-256
    * ECDSA certificates with key size <= 256 bits: SHA-256
    * ECDSA certificates with key size > 256 bits: SHA-512
* The v4 signature scheme digest algorithm is partly bases on the v2 or v3 and additionally uses always SHA-256 signatures
* There are options to manually override which signature schemes should be used. 
* There are options to control the minimum and maximum SDK versions instead of loading it from the AndroidManifest.xml
* The digest algorithm on APK signing is not configurable and most settings are determined automatically from the keys and SDK version. 

## JarSigner Behavior

Documentation about JAR signing is documented here: https://docs.oracle.com/javase/tutorial/deployment/jar/signindex.html

Documentation about the `jarsigner` tool is here: https://docs.oracle.com/en/java/javase/17/docs/specs/man/jarsigner.html

The following points describe how `jarsigner` behaves for scenarios where no explicit settings from outside are supplied and what manual options are available. 


* The documentation above shows that the `jarsigner` behaves similar to the `apksigner` in terms of default selection of digest algorithms but has more variations on the hash sizes used but generally SHA-256 or higher are available. 
* There are command line options available to determine legacy algorithms which are considered harmful: `jdk.jar.disabledAlgorithms` and `jdk.security.legacyAlgorithms`.
* There is a CLI option `-digestalg` which controls the digest algorithm used for the entries. `SHA-256` is the default if nothing is supplied.

## Signing Server Conclusion

* SigningServer uses the source code of `apksigner` which was semi-automatically translated from Java.

* The `v1` signature scheme is the standard JAR signing mechanism. 

* There are some slight differences in `apksigner` and `jarsigner` to the available digest algorithms. `jarsigner` already supports larger hashes while `apksigner` only supports `SHA-1` (legacy and deprecated) and `SHA-256`.

* There is currently direct demand for supporting `SHA-384` and `SHA-512` or signature algorithms like in `jarsigner`. The functionality of `apksigner` is sufficient.  

As a result Signing Server implements this behavior: 

* `.apk`
    * All signature schemes are enabled like it is the case for `apksigner` when calling it. No additional options can currently be supplied to SigningServer to control this behavior. 
    * The min-sdk-version is read from the `AndroidManifest.xml` and no manual option is available to define something different. Therefore it is required to have the file and this setting defined in the APK.
    * No manual selection of the digest algorithm is possible. Any provided input as part of signing requests is ignored and the default digest algorithm selection of `apksigner` is enabled. 
* `.aab`
    * For simplicity reasons they will be treated exactly like `.jar` files. 
* `.jar`
    * The signing will be performed by using the `v1` signature scheme signing mechanism of `apksigner`. 
    * As a result only `SHA-1` and `SHA-256` digest algorithms can be selected. 
    * If no custom digest algorithm is provided `SHA-256` will be used. 
    * If `.apk` files are renamed to `.jar` they will be treated like JARs and no auto detection for APK signing will happen. 