/**
 * @file   InitializationException.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class InitializationException
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

