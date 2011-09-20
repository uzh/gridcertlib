/**
 * @file   VomsProxyInit.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class VomsProxyInit
 *
 */
/* 
 * Copyright (c) 2010, 2011, ETH Zurich and University of Zurich.  All rights reserved.
 * 
 * This file is part of the GridCertLib software project.
 * You may copy, distribute and modify this file under the terms of
 * the LICENSE.txt file at the root of the project directory tree.
 *
 * $Id$
 */

package ch.swing.gridcertlib.django;
 
import ch.swing.gridcertlib.GridProxyFactory;

import java.util.Properties;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
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


    protected void doGetOrPost(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException
    {
        // Get the parameters from the URL query string, and pass them
        // unchanged to `GridProxyFactory.newProxy`.  Note that `vo`
        // is an array, so you one can query the servlet as
        // `http://....?vo=smscg&vo=life&....` to get a proxy with
        // default FQANs from both the `smscg` and the `life` VOs.
        // If there is no `vo` parameter, you get a non-VOMS proxy.
        final String credentialsPath = request.getParameter("store");
        if (null == credentialsPath || "".equals(credentialsPath))
            throwError("VomsProxyInit.doGetOrPost", 
                       "Missing required query parameter 'store' in HTTP request.");

        String nextUrl = request.getParameter("next");
        if (null == nextUrl || "".equals(nextUrl))
            throwError("VomsProxyInit.doGetOrPost", 
                       "Missing required query parameter 'next' in HTTP request.");
        try {
            nextUrl = URLDecoder.decode(nextUrl, "UTF-8");
        }
        catch (UnsupportedEncodingException ex) {
            throwError("SlcsInit.doGetOrPost",
                       "Cannot decode string '"
                       + nextUrl +
                       "' with UTF-8 encoding: " + ex.getMessage());
        }
            
        final String[] vo = request.getParameterValues("vo");
        for (String voname : vo) {
            ctx_.log("  VomsProxyInit: requesting FQAN: " + voname);
        }

        // extract the session key and password from a browser cookie
        String sessionId = null;
        String privateKeyPassword = null;
        for (Cookie cookie : request.getCookies()) {
            final String name = cookie.getName();
            // XXX: hard-coded value, should match what Python django-gridcertlib is doing
            if (name.equals("GridCertLib.privateKeyPassword")) {
                privateKeyPassword = cookie.getValue();
            };
            if (name.equals("GridCertLib.marker")) {
                sessionId = cookie.getValue();
            };
        }
        if (null == sessionId || sessionId.equals(""))
            throwError("VomsProxyInit.doGetOrPost", 
                       "Missing 'GridCertLib.marker' cookie.");
        if (null == privateKeyPassword)
            throwError("VomsProxyInit.doGetOrPost", 
                       "Cannot read private key password cookie.");

        // NOTE: We need to prevent that an HTTP GET to
        // http://...?store=/some/dir makes us overwrite files in an
        // aribtrary directory.  Thus we rely on Django to have
        // created a file named "__OK__<val>" where <val> is the value
        // passed through the "key" HTTP query paramater.  Since the
        // Django code will only create that subdirectory in the
        // intended directory, if it exists we can safely presume that
        // the HTTP request comes from a redirect issued by the Django
        // module and we are safe to process the "credentialsPath"
        // parameter.
        File marker = new File(credentialsPath + "/__OK__" + sessionId);
        if (! marker.exists()) {
            ctx_.log("SlcsInit.doGetOrPut(): Request for credentials store in '" + credentialsPath 
                     + "', but it does not contain the marker file for session '" + sessionId 
                     + "'. Ignoring possibly forged request.");
            throwError("VomsProxyInit.doGetOrPost", 
                       "Credential location '" + credentialsPath 
                       + "' cannot be trusted. Request forged?");
        }
            
        // XXX: hard-coded values, must match the ones in Python's "gridcertlib" module
        final String finalProxyPath = credentialsPath + "/userproxy.pem";
        final String certificatePath = credentialsPath + "/usercert.pem";
        final String privateKeyPath = credentialsPath + "/userkey.pem";

        ctx_.log("VomsProxyInit: using private key password '" + privateKeyPassword + "'");
        // Note: the `org.glite.voms.contact.VOMSProxyInit` class
        // reads some parameters from the following environment
        // variables / Java System properties: (there appears to
        // be no way of setting these by a method call).
        //
        // VOMSES_LOCATION      Directory where voms specification files are located (colon separated list of directories). Defaults to `$GLITE_LOCATION/etc/vomses`.
        // VOMSDIR              Directory where voms certificates are located. `Defaults to /etc/grid-security/vomsdir`
        // CADIR                Directory where CA certificates are stored; usual default is `/etc/grid-security/certificates`
        // 
        final String initialProxyPath = proxyFactory.newProxy(certificatePath, 
                                                              privateKeyPath, 
                                                              privateKeyPassword, 
                                                              vo);
        // move proxy to requested location
        File initialProxy = new File(initialProxyPath);
        File finalProxy = new File(finalProxyPath);
        boolean ok = initialProxy.renameTo(finalProxy);
        if (! ok)
            throwError("VomsProxyInit.doGetOrPost", 
                       "Could not move file '" + initialProxyPath 
                       + "' to final location '" + finalProxyPath + "'");

        // redirect to "next" URL
        response.sendRedirect(response.encodeRedirectURL(nextUrl));
        return;
    }


    /** Route HTTP GET requests to {@link #doGetOrPost}. */
    public void doGet(HttpServletRequest req, HttpServletResponse rsp)
        throws ServletException, IOException 
    {
        doGetOrPost(req,rsp);
    } 


    /** Route POST requests to {@link #doGetOrPost}. */
    public void doPost(HttpServletRequest req, HttpServletResponse rsp)
        throws ServletException, IOException 
    {
        doGetOrPost(req,rsp);
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
