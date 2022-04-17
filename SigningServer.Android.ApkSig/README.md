# Library description

This is a partial C# port of the official apksigner from Android available at https://android.googlesource.com/platform/tools/apksig

This library implements the single-certificate signing functionality only. Multi-Certificate signing and signature verification are not supported. 

## Motivation (Why porting to C# instead of wrapping the executable?)
This library is used in https://github.com/Danielku15/SigningServer to sign APKs on a centralized signing server that uses certificates from the windows certificate store.
apksigner does not support using certificates from the Windows Certificate Store which is a potential security risk when having certificates in files. Also apksigner requires
additionally Java and the Android SDK (at least the build tools) to be installed on the system. Having it as a DLL allows easier integration into the workflow. 