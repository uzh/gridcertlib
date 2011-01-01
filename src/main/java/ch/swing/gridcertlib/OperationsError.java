/**
 * @file   OperationsError.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class OperationsError
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
 * Signals an error during GridCertLib operations.  For instance, this
 * could be caused by a network error while contacting a server.
 * Instances of this class typically wrap the many kinds of exceptions
 * that can be raised during actual operations; inspect {@link
 * #getCause} to get the exception that generated this one.
 *
 * @author  riccardo.murri@gmail.com
 * @version $Revision$
 */
public class OperationsError 
    extends RuntimeException
{
    public OperationsError(final String explanation) 
    {
        super(explanation);
    }

    public OperationsError(final String explanation, 
                           final Throwable cause) 
    {
        super(explanation, cause);
    }

    public OperationsError(final Throwable cause) 
    {
        super(cause);
    }

    public OperationsError() 
    {
        super();
    }
}

