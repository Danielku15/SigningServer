# apksig-transpiler

This tool helps porting new versions of apksig semi-automatic from Java to C#.

It uses JavaParser to parse the code, and then feeds it through a custom transpilation to C#. 
Due to some limitations in JavaParser and also in the invested efforts, the output code is just a starting point for further manual porting to C#. But it does the heavy lifting. 

## Known Issues

* Implicit generic arguments on method calls and constructors are often not mapped correctly
* When primitive types are used in generics are changed to nullable versions. This is not always true.  
* When enums are used in switches this usually results in invalid switch statements. 
* Anonymous classes are not generated
* Lambdas are translated 1:1 while the related types might be interfaces.
* `@Override` will be taken over 1:1 even if they implement interface methods.