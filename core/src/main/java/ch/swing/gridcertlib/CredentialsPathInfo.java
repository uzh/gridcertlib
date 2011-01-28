/**
 * @file   CredentialsPathInfo.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class CredentialsPathInfo
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
 * CredentialsPathInfo provides a single place to store paths to the
 * certificate and key file, and the password to encrypt/decrypt the
 * private key.  Attributes cannot be altered after object
 * construction.
 *
 * @author  Riccardo Murri
 * @version $Revision$
 */
public class CredentialsPathInfo {

    private final String certificatePath_;
    private final String privateKeyPath_;
    private final String privateKeyPassword_;

    /** Constructor, taking certificate and private key file paths,
     * plus the password used to encrypt/decrypt the private key. 
     * None of the three fields can be altered after object construction.
     */
    public CredentialsPathInfo(final String certificatePath, 
                          final String privateKeyPath,
                          final String privateKeyPassword) 
    {
        certificatePath_ = certificatePath;
        privateKeyPath_ = privateKeyPath;
        privateKeyPassword_ = privateKeyPassword;
    }

    public String getCertificatePath()    { return certificatePath_; }
    public String getPrivateKeyPath()     { return privateKeyPath_; }
    public String getPrivateKeyPassword() { return privateKeyPassword_; }
}

