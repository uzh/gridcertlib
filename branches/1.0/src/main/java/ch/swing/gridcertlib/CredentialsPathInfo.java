/**
 * @file   CredentialsPathInfo.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class CredentialsPathInfo
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

