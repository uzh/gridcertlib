/**
 * @file   AssertionExpiredError.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class AssertionExpiredException
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

package ch.swing.gridcertlib;


/**
 * Thrown when the assertion gotten from the HTTP headers is expired
 * or otherwise no longer usable for authenticating to remote web
 * services.
 *
 * @author  riccardo.murri@gmail.com
 * @version $Revision$
 */
public class AssertionExpiredError
    extends OperationsError
{
    public AssertionExpiredError(final String explanation) 
    {
        super(explanation);
    }

    public AssertionExpiredError(final String explanation, 
                           final Throwable cause) 
    {
        super(explanation, cause);
    }

    public AssertionExpiredError(final Throwable cause) 
    {
        super(cause);
    }

    public AssertionExpiredError() 
    {
        super();
    }
}

