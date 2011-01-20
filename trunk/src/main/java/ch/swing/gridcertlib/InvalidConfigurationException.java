/**
 * @file   InvalidConfigurationException.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class InvalidConfigurationException
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

