/**
 * @file   VomsProxyInit.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class VomsProxyInit
 *
 */
/*
 * Copyright (c) 2010-2011 ETH Zurich and University of Zurich.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.swing.gridcertlib.servlet;
 
import ch.swing.gridcertlib.GridProxyFactory;

import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

 
/** Sample servlet for testing {@link ch.swing.gridcertlib.GridProxyFactory} functionality.
 * <p>
 * This is a simple interface to the {@link ch.swing.gridcertlib.GridProxyFactory#newProxy} 
 * method.  It runs {@link ch.swing.gridcertlib.GridProxyFactory#newProxy}, using 
 * query parameters to supply the function call arguments:
 * <ul>
 * <li> <code>certificatePath</code>: specifies the filesystem path to a PEM-encoded certificate file;
 * <li> <code>privateKeyPath</code>: specifies the filesystem path to a PEM-encoded private key file;
 * <li> <code>privateKeyPassword</code>: the password to decrypt the private key file;
 * <li> <code>vo</code> (optional): if present, specifies the VO to request VOMS attributes from; 
 *      if given multiple times, VOMS ACs are requested for all the listed VOs;
 * <li> <code>lifetime</code> (optional): if present, specifies the lifetime (in seconds) of the VOMS AC.
 * </ul>
 * Upon successful creation of a VOMS proxy, displays the filesystem
 * path to the file where the proxy is stored.
 * <p>
 * In contrast to other servlets in this package, this one does not
 * need access to any information provided by Shibboleth.
 * <p>
 * This servlet is provided as sample code to use GridCertLib's
 * functionality; it should not be used in any production environment.
 *
 * @see ch.swing.gridcertlib.GridProxyFactory
 * @see SlcsInit
 */ 
public class VomsProxyInit extends HttpServlet
{
    /** Factory for generating proxy certificates. */
    protected GridProxyFactory proxyFactory;

    /** Servlet context. Used for logging. */
    protected ServletContext ctx_;


    public void init(ServletConfig conf) 
        throws ServletException 
    {
        ctx_ = conf.getServletContext();

        // Load properties to initialize GridCertLib's GridProxyFactory;
        // the location of the properties file is given by Servlet
        // init parameter "GridcertlibPropertiesFile" (look into
        // src/main/rources/override-web.xml).  GridProxyFactory could be
        // initialized by giving the full list of required parameters
        // instead of a property object.
        final Properties props = new Properties();
        final String propertiesFile = conf.getInitParameter("GridcertlibPropertiesFile");
        if (null == propertiesFile)
            throwError("VomsProxyInit.init", "Missing required init parameter 'GridcertlibPropertiesFile'");
        try {
            props.load(new FileInputStream(propertiesFile));
        }
        catch (java.io.FileNotFoundException x) {
            throwError("VomsProxyInit.init", 
                       "Properties file '" + propertiesFile
                       + "' referenced by init parameter 'GridcertlibPropertiesFile' does not exist");
        }
        catch (java.io.IOException x) {
            throwError("VomsProxyInit.init", 
                       "Got IOException while loading properties from file '"
                       + propertiesFile
                       + "': " + x.getMessage());
        };

        proxyFactory = new GridProxyFactory(props);

        super.init(conf);
     }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException
    {
        // Get the parameters from the URL query string, and pass them
        // unchanged to `GridProxyFactory.newProxy`.  Note that `vo`
        // is an array, so you one can query the servlet as
        // `http://....?vo=smscg&vo=life&....` to get a proxy with
        // default FQANs from both the `smscg` and the `life` VOs.
        // If there is no `vo` parameter, you get a non-VOMS proxy.
        try {
            final String certificatePath = getRequiredParameter(request, "certificatePath");
            final String privateKeyPath = getRequiredParameter(request, "privateKeyPath");
            final String privateKeyPassword = getRequiredParameter(request, "privateKeyPassword");
            final String[] vo = request.getParameterValues("vo");

            // Note: the `org.glite.voms.contact.VOMSProxyInit` class
            // reads some parameters from the following environment
            // variables / Java System properties: (there appears to
            // be no way of setting these by a method call).
            //
            // VOMSES_LOCATION      Directory where voms specification files are located (colon separated list of directories). Defaults to `$GLITE_LOCATION/etc/vomses`.
            // VOMSDIR              Directory where voms certificates are located. `Defaults to /etc/grid-security/vomsdir`
            // CADIR                Directory where CA certificates are stored; usual default is `/etc/grid-security/certificates`
            // 
            String proxyPath = proxyFactory.newProxy(certificatePath, 
                                                     privateKeyPath, 
                                                     privateKeyPassword, 
                                                     vo);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/plain");
            response.getWriter().println("Proxy file path: '" + proxyPath + "'");
        }
        catch (NoSuchFieldException x) {
            throwError("VomsProxyInit.doGet", 
                       "Missing required query parameter: " + x.getMessage());
        };
    }


    protected String getRequiredParameter(HttpServletRequest request, final String name)
        throws NoSuchFieldException
    {
        final String result = request.getParameter(name);
        if (null == result)
            throw new NoSuchFieldException(name);
        else
            return result;
    }


    /** Convenience method for logging an error and throwing a {@link
     * javax.servlet.ServletException}. 
     */
    protected void throwError(final String source, final String message) 
        throws ServletException
    {
        ctx_.log(source + ": ERROR: " + message);
        throw new ServletException(message);
    }
}
