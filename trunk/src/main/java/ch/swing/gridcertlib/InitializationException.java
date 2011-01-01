/**
 * @file   InitializationException.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class InitializationException
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
 * Signals an error during the initialization of a factory object.
 * Also used as a wrapper class around many kinds of exceptions that
 * can be raised during class initialization; to get the original exception that
 * this class wraps around, inspect {@link #getCause}.
 *
 * @author  riccardo.murri@gmail.com
 * @version $Revision$
 */
public class InitializationException 
    extends RuntimeException
{

    public InitializationException(final String explanation) 
    {
        super(explanation);
    }

    public InitializationException(final String explanation, 
                                   final Throwable cause) 
    {
        super(explanation, cause);
    }

    public InitializationException(final Throwable cause) 
    {
        super(cause);
    }

    public InitializationException() 
    {
        super();
    }
}

