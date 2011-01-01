/**
 * @file   InvalidConfigurationException.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class InvalidConfigurationException
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
 * Signals an error in a configuration file, e.g., a missing required parameter.
 *
 * @author  riccardo.murri@gmail.com
 * @version $Revision$
 */
public class InvalidConfigurationException 
    extends InitializationException
{

    public InvalidConfigurationException(final String explanation) 
    {
        super(explanation);
    }

    public InvalidConfigurationException(final String explanation, 
                                         final Throwable cause) 
    {
        super(explanation, cause);
    }

    public InvalidConfigurationException(final Throwable cause) 
    {
        super(cause);
    }

    public InvalidConfigurationException() 
    {
        super();
    }
}

