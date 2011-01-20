/**
 * @file   OperationsError.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class OperationsError
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

