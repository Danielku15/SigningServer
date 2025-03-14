# SigningServer Self-Contained Client

This is a NuGet package for consuming self-contained SigningServer.Client executables which do not need any .net runtime installed.

This package is useful if you want to consume the signing client from a platform having .net installed,
but then passing it to an environment without .net (e.g. within a Docker container).

## Security Note

These packages bundle the latest .net runtime available during the release. With Self Contained applications
you do not benefit from Updates and Security patches on the .net runtime.

If you need a release with newer/alternative runtime versions embedded, open an issue at https://github.com/Danielku15/SigningServer/issues

You can also vote for [this improvement](https://github.com/Danielku15/SigningServer/issues/62) to automate the process.

## Consuming

To consume this package you need some mechanism of restoring a .net package locally.
Either you might do this manually and use the binaries directly, or you might install
this package in a C# project belonging to your CI/CD pipeline (e.g. when using Nuke).

## Usage PackageReference - MSBuild Props

If you consume this package via a `PackageReference` you will have following MSBuild properties available in this `csproj`
for passing it further to your application via custom means.

* `SigningServerClientBasePath` - The root path to this nuget package for manual traversal.
* `SigningServerClientToolBasePath` - The root path in which the RID specific platform binaries are placed.
* `SigningServerClientToolPath` - The root path of the platform binaries for the currently executing host environment.
* `SigningServerClientExecutableName` - The name of the main signing server executable (without file extension - e.g. `SigningServer.Client`)
* `SigningServerClientExecutableFileName` - The file name of the main signing server executable (with file extension matching the runtime identifier - e.g. `SigningServer.Client.exe` on windows)

## Usage PackageReference - GeneratePathProperty

You can also use [`GeneratePathProperty`](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#generatepathproperty)
to traverse the folder structure yourself.

## Folder Structure in this Package

Info: Descriptions are at the end as `// description`

```
root/
├─ build/
│  ├─ SigningServer.StandaloneClient.props // the MSBuild props file - automatically imported into csprojs
├─ tools/                                  // Entry point for platform specific folders 

│  ├─ linux-x64/                           // Multiple platform specific folders with binaries you need to copy for execution 
│  │  ├─ SigningServer.Client              // The main executable binary for the signing client (might need to set chmod for execution) 
│  │  ├─ libcoreclr.so                     // potential runtime dependencies which you need to copy along for execution 
│  │  ├─ ... 

│  ├─ win-x64/                             // folder for every supported RID 
│  │  ├─ SigningServer.Client.exe          // The main executable binary for the signing client
│  │  ├─ coreclr.dll                       // potential runtime dependencies which you need to copy along for execution
│  │  ├─ ...
```
