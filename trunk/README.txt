The GridCertLib library
=======================

This is the source tree of GridCertLib, a Java library providing
services to create a SLCS/X.509 certificate and a Grid proxy
(optionally VOMS-enabled), given the SAML2 assertion resulting from a
Shibboleth2 authentication.

The library comes with some example servlets (cf. package
`ch.swing.gridcertlib.servlet`) that provide sample code to use the
GridCertLib features in a Java web services environment.


Quickstart
----------

In order to build the library code and documentation, you need to
haven Maven 2 installed. (see: http://maven.apache.org/ )
The Maven project file lists the compile- and run-time dependencies;
`.jar` files that are not available from online Maven repositories are
included in the `lib/` subdirectory.

To build documentation, issue the following command:

  mvn javadoc:javadoc

The HTML documentation can then be found in directory
`target/site/apidocs`.  The package `ch.swing.gridcertlib` overview
provides an introduction to the library usage; package
`ch.swing.gridcertlib.servlet` briefly introduces the example servlets
and discusses deployment requirements and caveats.

To compile the library and make a jar file, issue the following
command: 

  mvn jar:jar

The resulting `.jar` file can be found in directory `target/`.



Copyright and license
---------------------

Copyright (c) 2010, ETH Zurich and University of Zurich.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
