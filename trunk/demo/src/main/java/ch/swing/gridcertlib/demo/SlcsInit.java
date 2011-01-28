/**
 * @file   SlcsInit.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class SlcsInit
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

package ch.swing.gridcertlib.demo;

import ch.swing.gridcertlib.AssertionExpiredError;
import ch.swing.gridcertlib.CredentialsPathInfo;
import ch.swing.gridcertlib.InitializationException;
import ch.swing.gridcertlib.InvalidConfigurationException;
import ch.swing.gridcertlib.OperationsError;
import ch.swing.gridcertlib.SLCSFactory;
import ch.swing.gridcertlib.servlet.RenewAssertion;

import ch.SWITCH.aai.idwsf.token.AssertionException;

import java.io.UnsupportedEncodingException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/** Sample servlet for creating a new SLCS certificate/private key pair.
 * <p>
 * Reads the SAML assertion URL from the Shibboleth information
 * available into the HTTP request and tries to get a new SLCS
 * certificate with it. Upon successful completion, outputs the
 * location of the certificate and key files, and the (random)
 * password used to encrypt the private key.
 * <p>
 * This servlet is provided as sample code to use GridCertLib's
 * functionality; it should not be used in any production environment.
 *
 * @see ch.swing.gridcertlib.SLCSFactory
 * @see RenewAssertion
 * @see VomsProxyInit
 */ 
public class SlcsInit extends HttpServlet
{
    /** Visible URL of the {@link RenewAssertion} servlet.  This is
     * the URL that client browsers connect to; it will be different
     * from the URL returned by the servlet container if a proxy
     * frontend is used. 
     */
    protected String renewAssertionUrl_;

    /** Visible URL of this servlet.  This is the URL that client
     * browsers connect to; it will be different from the URL returned
     * by the servlet container if a proxy frontend is used.  If
     * {@code null}, then {@link
     * javax.servlet.http.HttpServletRequest#getRequestURL} is used to
     * compute it. 
     */
    protected String visibleUrl_;

    /** Factory for generating SLCS certificates. */
    protected SLCSFactory slcs;
    
    /** Servlet context. Used for logging. */
    protected ServletContext ctx_;

    public void init(ServletConfig conf) 
        throws ServletException 
    {
        ctx_ = conf.getServletContext();

        // Load properties to initialize GridCertLib's SLCSFactory;
        // the location of the properties file is given by Servlet
        // init parameter "GridcertlibPropertiesFile" (look into
        // src/main/rources/override-web.xml).  SLCSFactory could be
        // initialized by giving the full list of required parameters
        // instead of a property object.
        final Properties props = new Properties();
        final String propertiesFile = conf.getInitParameter("GridcertlibPropertiesFile");
        if (null == propertiesFile)
            throwError("SlcsInit.init", "Missing required init parameter 'GridcertlibPropertiesFile'");
        try {
            props.load(new FileInputStream(propertiesFile));
        }
        catch (java.io.FileNotFoundException x) {
            throwError("SlcsInit.init", 
                       "Properties file '" + propertiesFile
                       + "' referenced by init parameter 'GridcertlibPropertiesFile' does not exist");
        }
        catch (java.io.IOException x) {
            throwError("SlcsInit.init", 
                       "Got IOException while loading properties from file '"
                       + propertiesFile
                       + "': " + x.getMessage());
        };

        // Initialization of the SLCSFactory object.  Only one such
        // factory instance is needed portal-wide; more than one can
        // be instanciated if you need to cater for different
        // server-side parameters (e.g., virtual host names, different
        // SLCS endpoints depending on user IdP, etc.)  By default,
        // SLCSFactory bootstraps the OpenSAML library, but this can
        // be turned off by using an alternate constructor.
        try {
            ctx_.log("SlcsInit.init(): Creating SLCSFactory (will bootstrap OpenSAML as well)...");
            slcs = new SLCSFactory(props);
        } catch (InvalidConfigurationException x) {
            throwError("SlcsInit.init", "Invalid value in configuration data: " + x.getMessage());
        } catch (InitializationException x) {
            throwError("SlcsInit.init", "Got SLCSFactory initialization error: " + x.getMessage());
        };

        // The visible URL of the RenewAssertion servlet is needed to
        // redirect browsers when the assertion data is expired.
        renewAssertionUrl_ = conf.getInitParameter("RenewAssertionURL");
        if (null == renewAssertionUrl_) {
            throwError("SlcsInit.init", "Missing required init parameter 'RenewAssertionURL'");
        };

        // Likewise, the visible URL of this servlet is needed to
        // provide the return address after assertion renewal.
        visibleUrl_ = conf.getInitParameter("VisibleURL");
        if (null == visibleUrl_)
            ctx_.log("SlcsInit: WARNING: No `VisibleURL` init parameter set, may not work if the servlet container is behind a forward proxy");

        super.init(conf);
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException
    {
        ctx_.log("Running SlcsInit.doGet() ...");

        // There can be more than one assertion; the exact number is
        // stored in the `Shib-Assertion-Count` HTTP header.
        String count_ = request.getHeader("Shib-Assertion-Count");
        if (null == count_) 
            throw new ServletException("Cannot read assertions count from HTTP header 'Shib-Assertion-Count'");
        int count = Integer.parseInt(count_, 10);
        if (count < 1) // Should not happen: if there's no assertion, there's no "Shib-Assertion-Count"
            throw new ServletException("Count of assertions in HTTP header 'Shib-Assertion-Count' is 0");
        ctx_.log("SlcsInit.doGet(): Shib-Assertion-Count=" + count);

        // Retrieve SAML2 assertion URL; Apache needs to be configured
        // with "ShibExportAssertion On" for this to work.  In case
        // there are >1 assertions, we just pick the first.  A more
        // sophisticated servlet could select according to some other
        // criteria, or let user select one, or just try them all in
        // turn...
        String samlAssertionUrl = request.getHeader("Shib-Assertion-01");
        if (null == samlAssertionUrl)
            throw new ServletException("Cannot read assertion from HTTP header 'Shib-Assertion-01'");
        ctx_.log("SlcsInit.doGet(): Shib-Assertion-01='" + samlAssertionUrl +"'");

        // This is the core of the servlet: `SLCSFactory.newSLCS()`
        // generates a new SLCS certificate and writes it to disk, or
        // throws an exception in case of failure.  The returned
        // `CertificatePathInfo` object is a read-only triple
        // providing access to the filesystem location of certificate
        // and key, and the password used to encrypt the key.  It is
        // possible to explicitly specify certificate file location,
        // key location and password by using alternate forms of the
        // `newSLCS` method.
        try {
            CredentialsPathInfo pathsInfo = slcs.newSLCS(samlAssertionUrl);

            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("text/plain");
            response.getWriter().println("Certificate path: " + pathsInfo.getCertificatePath());
            response.getWriter().println("Private key path: " + pathsInfo.getPrivateKeyPath());
            response.getWriter().println("Private key password path: " + pathsInfo.getPrivateKeyPassword());
            return;
        }
        // The SAML assertion has limited time validity (default: 5
        // minutes) to mitigate risks that a rogue can steal it and
        // reuse, but the SP session is normally much longer (default:
        // 8 hours).  So, unless this servlet is called exactly at the
        // beginning of the Shibboleth session, there is quite a
        // chance that the assertion is not usable any longer.  The
        // `RenewAssertion` servlet is provided exactly for this
        // purpose: it forces an SP session logout, and then redirects
        // to a Shibboleth-protected location, so that a new assertion
        // will be requested by the SP to the IdP; as long as the IdP
        // session is still alive, users will not be asked for login
        // data again.  So, the solution is to redirect onto the
        // `RenewAssertion` address, and then ask `RenewAssertion` to
        // redirect back to here when done.
        catch (AssertionExpiredError e) {
            String returnUrl;
            if (null == visibleUrl_)
                returnUrl = request.getRequestURL().toString();
            else
                returnUrl = visibleUrl_;

            // Redirect to the `RenewAssertion` servlet.  The query
            // URL must be formatted in a specific way, embedding the
            // return address in hex-encoded format; the
            // `RenewAssertion.getRenewalUrl()` convenience method is
            // provided exactly for this purpose.
            try {
                final String redirectUrl = RenewAssertion.getRenewalUrl(returnUrl, renewAssertionUrl_);
                response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
                response.addHeader("Location", redirectUrl);
                response.setContentType("text/html");
                response.getWriter().println("Assertion expired, please click <a href=\"" 
                                             + redirectUrl
                                             + "\">here</a> to continue.");
                return;
            }
            // This should never happen in practice, as for web
            // operations we have to use the UTF-8 encoding that is
            // included in any Java install, but the compiler forces
            // us to intercept the exception...
            catch (UnsupportedEncodingException x) {
                throw new ServletException("Got UnsupportedEncodingException while encoding string '" 
                                           + returnUrl
                                           + "' with UTF-8 charset:" + x.getMessage(), x);
            }
        }
        // Any error during the `slcs-init` procedure (e.g., network
        // error, authentication error to the SLCS server, disk or I/O
        // error when saving files, etc.) winds up as an
        // `OperationsError`.  Use the `.getCause()` method to extract
        // the root exception.
        catch (OperationsError x) {
            throw new ServletException("Got SLCS OperationsError: " + x.getMessage(), x);
        }
        // code path should never get here
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
