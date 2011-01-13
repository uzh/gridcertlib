/**
 * @file   RenewAssertion.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class RenewAssertion
 *
 */
/* 
 * Copyright (c) 2010, ETH Zurich and University of Zurich.  All rights reserved.
 * 
 * This file is part of the GridCertLib software project.
 * You may copy, distribute and modify this file under the terms of
 * the LICENSE.txt file at the root of the project directory tree.
 *
 * $Id$
 */

package ch.swing.gridcertlib.servlet;

import org.bouncycastle.util.encoders.Hex;

import java.io.UnsupportedEncodingException;
import java.util.Properties;
import java.io.InputStream;
import java.io.IOException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

 
/** Force SP session logout and then login again, finally redirect
 * browser to the address specified in the {@code return} query parameter.
 * Logging out of the SP session and then in again ensures that we get
 * a fresh SAML assertion from the IdP; when the IdP session expires,
 * this will actually prompt the user for a new login procedure.
 * <p>
 * Final redirect via the {@code return} URL query parameter is
 * provided so that only this servlet needs to be
 * Shibboleth-protected, whereas the majority of portal pages can just
 * use the native session management protocol.
 * <p>
 * In detail, this servlet does the following:<ol>
 * <li>Responds to a request made by another servlet: the request URL
 *     is this servlet's URL plus the string "/do/" followed by the
 *     return URL, encoded with {@link #encodeUrl} (note that the
 *     encoding scheme currently uses two characters in the encoded
 *     URL for each character in the original one).
 * <li>Redirect browser to the {@code
 *     http://.../Shibboleth.sso/Logout} URL, forcing SP session
 *     logout, asking for return to this servlet's URL (with the final
 *     destination URL embedded into the path info part of the URL).
 * <li>The {@code Logout} page redirects back to this servlet, which
 *     is Shibboleth-protected, so the SP initiates a new session and 
 *     gets a fresh assertion from the IdP.
 * <li>Read the return URL from the path info, decode it, and redirect
 *     browser to that URL.
 * </ol>
 * <p>
 * The following servlet init parameters are required:<ul>
 * <li>{@code ShibbolethLogoutURL} URL to initiate Shibboleth SP
 *     session logout (usually, this is {@code
 *     http://hostname/Shibboleth.sso/Logout})
 * <li>{@code RenewAssertionURL} visible URL of this servlet (may be
 *     different from the one returned by the servlet container's
 *     {@code javax.servlet.HttpServletRequest#getRequestURL} because of proxying)
 * </ul>
 * <p>
 * This servlet is provided as sample code to use GridCertLib's
 * functionality; it should not be used in any production environment.
 *
 * @see SlcsInit
 */ 
public class RenewAssertion extends HttpServlet
{
    protected static final String RETURN_URL_ATTRIBUTE_NAME = "org.swing.gridcertlib.servlet.RenewAssertion.return";

    /** The URL to the Shibboleth SP logout request. (Usually {@code
     * http://hostname/Shibboleth.sso/Logout}) Initialized from the
     * {@code ShibbolethLogoutURL} servlet init parameter.
     */
    protected String logoutUrl_;

    /** The visible URL of this servlet. (We cannot get this from
     * {@code javax.servlet.HttpServletRequest#getRequestURL} --
     * proxying would fool us.)  Initialized from the {@code
     * RenewAssertionURL} servlet init parameter.
     */
    protected String selfUrl_;

    /** Servlet context.  Used for logging. */
    protected ServletContext ctx_;


    public void init(ServletConfig conf) 
        throws ServletException 
    {
        ctx_ = conf.getServletContext();

        // Load servlet init parameters. (If you run this with {@code
        // mvn jetty:run} then look into
        // {@code src/main/resources/override-web.xml})
        try {
            logoutUrl_ = getRequiredInitParameter(conf, "ShibbolethLogoutURL");
            selfUrl_ = getRequiredInitParameter(conf, "RenewAssertionURL");
        }
        catch (NoSuchFieldException x) {
            throw new ServletException("Missing required init parameter '" + x.getMessage() + "'");
        };
        
        super.init(conf);
     }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException
    {
        // A request to this servlet must have the form
        // <RenewAssertionURL>/<action>/<hex-encoded
        // return URL> (such URLs can be constructed using the
        // `RenewAssertion.getRenewalUrl` method).  By construction,
        // the <action>/<return URL> part is available
        // as the HTTP request's "path information".
        final String pathInfo = request.getPathInfo();
        String action, encodedDestinationUrl;
        if (null == pathInfo) 
            throw new ServletException("Malformed request: null URL path info");
        else {
            // get phase and return URL from query URL
            String[] parts = pathInfo.split("/+", 3);
            if (parts.length < 3)
                throw new ServletException("Malformed request: URL path information must contain at least two components, has " + parts.length + " instead");
            // parts[0] is always the empty string, since "path info" is guaranteed to begin with `/`
            action = parts[1];
            encodedDestinationUrl = parts[2];
        };

        // The <action> part is used to determine whether the browser
        // is returning here after logout/login.
        if (action.equals("do")) {
            // New visit, redirect to SP logout URL and ask it to
            // redirect back to here, but change the <action> field to
            // "done".  (Incidentally, this is the main reason for using this
            // strange encoding of the requests in the URL: we cannot
            // pass a URL with a query part as argument to the
            // `return` parameter, yet we need to know what is the
            // original return location -- therefore we use a return
            // URL that has it appended as part of the path info.)
            final String redirectUrl = logoutUrl_ + "?return=" + selfUrl_ + "/done/" + encodedDestinationUrl;
            ctx_.log("RenewAssertion: initiating logout, redirecting to " + redirectUrl);
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.addHeader("Location", redirectUrl);
            response.setContentType("text/html");
            response.getWriter()
                .println("<html><body>"
                         + "Renewing authorization data, please click <a href=\"" 
                         + redirectUrl
                         + "\">here</a> to continue."
                         + "</body></html>");
        }
        else if (action.equals("done")) {
            // Browser is coming back after SP session logout/login;
            // decode the original return URL and redirect to it.
            String decodedDestinationUrl;
            try {
                decodedDestinationUrl = decodeUrl(encodedDestinationUrl);
            }
            catch (UnsupportedEncodingException x) {
                throw new ServletException("Got UnsupportedEncodingException while decoding string '" 
                                           + encodedDestinationUrl 
                                           + "' with UTF-8 charset:" + x.getMessage(), x);
            }

            ctx_.log("RenewAssertion: returning client, redirect to " + decodedDestinationUrl);
            response.setStatus(HttpServletResponse.SC_MOVED_TEMPORARILY);
            response.addHeader("Location", decodedDestinationUrl);
            response.setContentType("text/html");
            response.getWriter()
                .println("<html><body>"
                         + "Renewed authorization data, please click <a href=\"" 
                         + decodedDestinationUrl
                         + "\">here</a> to continue."
                         + "</body></html>");
        }
        else
            throw new ServletException("Malformed request to RenewAssertion: action field must be one of 'do', 'done'");
    }

    /** Get the URL to renew the assertion in the SP session and then
     * get back to {@code destinationUrl}. 
     */
    public static String getRenewalUrl(final String destinationUrl, 
                                       final String renewAssertionUrl)
        throws UnsupportedEncodingException
    {
        return renewAssertionUrl + "/do/" + encodeUrl(destinationUrl);
    }

    protected static String encodeUrl(final String decoded)
        throws UnsupportedEncodingException
    {
        return new String(Hex.encode(decoded.getBytes("UTF-8")), "UTF-8");
    }

    protected static String decodeUrl(final String encoded)
        throws UnsupportedEncodingException
    {
        return new String(Hex.decode(encoded), "UTF-8");
    }

    protected String getRequiredInitParameter(final ServletConfig conf, 
                                              final String name)
        throws NoSuchFieldException
    {
        final String result = conf.getInitParameter(name);
        if (null == result)
            throw new NoSuchFieldException(name);
        else
            return result;
    }

    protected void throwError(final String source, final String message) 
        throws ServletException
    {
        ctx_.log(source + ": ERROR: " + message);
        throw new ServletException(message);
    }
}
