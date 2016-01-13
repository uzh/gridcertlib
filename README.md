# The GridCertLib library #

This is the source tree of GridCertLib, a Java library providing
services to create a SLCS/X.509 certificate and a Grid proxy
(optionally VOMS-enabled), given the SAML2 assertion resulting from a
Shibboleth2 authentication.  The
[presentation](docs/slides/egi-tf2011/rmurri-gridcertlib-egitf2011.pdf)
held at the [EGI Technical Forum 2011](http://tf2011.egi.eu/) is
probably the best exposition of the "what" and "why" of GridCertLib.

The library comes with some example servlets (cf. package
`ch.swing.gridcertlib.servlet`) that provide sample code to use the
GridCertLib features in a Java web services environment.

See below for a longer explanation and installation instructions.


## So, what is GridCertLib again? ##

GridCertLib is a Java library providing services to create a
SLCS/X.509 certificate and a Grid proxy (optionally VOMS-enabled),
given the SAML2 assertion resulting from Shibboleth2 authentication.

The library was written with a specific use-case in mind: use within a
portal or web application.  The programming interface has thus been
kept generic, in order to adapt to the various programming paradigms
used by different host products.  The only hard requirement is that
X.509 certificates and proxies can be stored on the filesystem.

The main use case envisioned for GridCertLib is to provide seamless
and secure access to Grid/X.509 certificates and proxies in web
portals: when a user logs in to the portal using regular Shibboleth
authentication, GridCertLib can automatically obtain a Grid X.509
certificate from a SLCS service and generate a VOMS proxy from
it. Moreover, all of this can happen without further interaction with
the user.

The most complete description of GridCertLib's architecture and usage
is given in [arXiv paper 1101.4116](http://arxiv.org/abs/1101.4116).

Feel free to [write
us](mailto:riccardo.murri@gmail.com,sergio.maffioletti@uzh.ch,peter.kunszt@systemsx.ch)
for any information or feedback!


## Installing and using GridCerLib ##

### Prerequisites ###

GridCertLib depends on several other packages. Most of them are
available in the Maven repository referenced by GridCertLib's
`pom.xml` file, so the easiest way to get them is to let Maven perform
the download.

Others are not; download URLs are summarized in the table below:

| **Package**     | **Version**    | **Download URL**      | **Notes**  |
|:----------------|:---------------|:----------------------|:-----------|
| vomsjapi        | >= 1.9.17.1    | http://etics-repository.cern.ch/repository/download/registered/org.glite/org.glite.security.voms-api-java/1.9.17/noarch/glite-security-voms-api-java-1.9.17-1.tar.gz/-/share/java/vomsjapi.jar | RPM packages available from: http://pkgs.org/package/vomsjapi |
| glite-slcs-ui   | 1.4.1          | http://etics-repository.cern.ch/repository/download/registered/org.glite/org.glite.slcs.ui/1.4.1/noarch/glite-slcs-ui-1.4.1-1.tar.gz/-/share/java/glite-slcs-ui.jar |            |
| glite-slcs-common | 1.6.1          | http://etics-repository.cern.ch/repository/download/registered/org.glite/org.glite.slcs.common/1.6.1/noarch/glite-slcs-common-1.6.1-1.tar.gz/-/share/java/glite-slcs-common.jar |            |
| bcprov-1.37     | 1.37           | http://etics-repository.cern.ch/repository/download/registered/org.glite/org.glite.slcs.ui/1.4.1/noarch/glite-slcs-ui-1.4.1-1.tar.gz/-/share/glite-slcs-ui/java/bcprov-1.37.jar | Needed by glite-slcs-ui and the servlet code in GridCertLib |
| cog-jglobus     | 1.8.0          | http://www.globus.org/cog/distribution/1.8.0/cog-jglobus-1.8.0-bin.tar.gz | JAR file available in the `lib/` subdirectory of archive; see also: http://dev.globus.org/wiki/CoG_JGlobus_1.8.0 |
| jgss            | 1.8.0          | http://www.globus.org/cog/distribution/1.8.0/cog-jglobus-1.8.0-bin.tar.gz | JAR file available in the `lib/` subdirectory of archive; see also: http://dev.globus.org/wiki/CoG_JGlobus_1.8.0 |


### Building from sources ###

In order to build the library code and documentation, you need to
haven [Maven 2](http://maven.apache.org/) installed.
The Maven project file lists the compile- and run-time dependencies;
`.jar` files that are not available from online Maven repositories are
included in the `lib/` subdirectory.

Not all GridCertLib dependencies are available from Maven repositories;
please follow the instructions in section *Prerequisites* above.

GridCertLib is built using the standard Maven goals;
if you're new to Maven, here's a quick start:

* To compile the library and make a jar file, issue the following
  command::

        mvn jar:jar

  The resulting `.jar` file can be found in directory `target/`.

* To build documentation, issue the following command::

        mvn javadoc:javadoc

  The HTML documentation can then be found in directory
  `target/site/apidocs`.  The package `ch.swing.gridcertlib` overview
  provides an introduction to the library usage; package
  `ch.swing.gridcertlib.servlet` briefly introduces the example
  servlets and discusses deployment requirements and caveats.


## Copyright and license ##

Copyright (c) 2010, ETH Zurich and University of Zurich.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
