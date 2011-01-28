/**
 * @file   PrintHeaders.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class PrintHeaders
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

import ch.swing.gridcertlib.SLCSFactory;
 
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
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


/** Log init parameters and HTTP request headers, and also dump them
 * into the HTTP response. Use as a debugging aid; no real production
 * use. 
 */ 
public class PrintHeaders extends HttpServlet
{
    /** Servlet context. Used for logging. */
    protected ServletContext ctx_;

    public void init(ServletConfig conf) throws ServletException {
        ctx_ = conf.getServletContext();

        ctx_.log("Starting PrintHeaders.init() ...");
        List<String> params = Collections.list((Enumeration<String>)conf.getInitParameterNames());
        for (String name : params) {
            ctx_.log("  PrintHeaders.init(): Got init parameter " + name + "='" + ctx_.getInitParameter(name) + "'");
        };
        
        final Properties props = new Properties();
        final String propertiesFile = conf.getInitParameter("GridcertlibPropertiesFile");
        if (null == propertiesFile)
            throwError("PrintHeaders.init", "Missing required init parameter 'GridcertlibPropertiesFile'");
        ctx_.log("PrintHeaders.init() loading gridcertlib.properties from file '" 
                + propertiesFile + "'...");
        try {
            props.load(new FileInputStream(propertiesFile));
        }
        catch (java.io.FileNotFoundException x) {
            throwError("PrintHeaders.init", 
                       "Properties file '" + propertiesFile
                       + "' referenced by init parameter 'GridcertlibPropertiesFile' does not exist");
        }
        catch (java.io.IOException x) {
            throwError("PrintHeaders.init", 
                       "Got IOException while loading properties from file '"
                       + propertiesFile
                       + "': " + x.getMessage());
        };

        super.init(conf);
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
        throws ServletException, IOException
    {
        response.setContentType("text/plain");
        response.setStatus(HttpServletResponse.SC_OK);

        response.getWriter().println("=== HTTP request headers ==="); 
        List<String> headers = Collections.list((Enumeration<String>)request.getHeaderNames());
        for (String name : headers) {
            response.getWriter().println(name + ": '" + request.getHeader(name) + "'");
        };
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
