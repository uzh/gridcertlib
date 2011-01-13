/**
 * @file   SLCSFactory.java
 * @author riccardo.murri@gmail.com, peter.kunszt@systemsx.ch, valery.tschopp@switch.ch
 *
 * Source code for class SLCSFactory; part of this code imported
 * originally from the {@link org.glite.slcs.ui} package.
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

import ch.SWITCH.aai.idwsf.ecp.WebServiceClient;
import ch.SWITCH.aai.idwsf.token.SAML2AssertionURLResolver;
import ch.SWITCH.aai.idwsf.token.TokenResolverException;
import ch.SWITCH.aai.idwsf.xml.OpenSAML;
import ch.SWITCH.httpclient.tls.PEMTLSCredentials;
//import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.bouncycastle.openssl.PEMWriter;
import org.glite.slcs.SLCSException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


/**
 * Façade to request SLCS certificates and store them to a chosen
 * location on the filesystem.
 * <p>
 * A single instance of the class can generate multiple certificates
 * (possibly for different users) via repeated invocation of the 
 * {@link #newSLCS} method. 
 * <p>
 * Several instances of the same class can operate at the same time,
 * allowing one to get SLCS certificates from different endpoints, or
 * to serve users from different federations.
 * 
 * @see #SLCSFactory(String,String,String,String,String,String,String,String,int,boolean)
 * @see #SLCSFactory(Properties,boolean)
 * @see #newSLCS(String,String,String,String)
 * @see #newSLCS(String)
 */
public class SLCSFactory {

    /** Logging */
    static Logger LOG = LoggerFactory.getLogger(SLCSFactory.class);

    /** Default number of backup file to keep */
    static int MAX_BACKUP = 3;

    /** Absolute pathname of directory to store user key and cert */
    protected String defaultStoreDirectory_;

    /** Default private key size. */
    protected final int defaultPrivateKeySize_;

    /** URL to the SLCS service login. */
    protected final String slcsLoginUrl_;

    /** URL to the WSP Session Initiator (typically ends with `.../Shibboleth.sso/WSP`) */
    protected final String wspSessionInitiatorUrl_;

    /** ID-WSF ECP Web Service Client */
    protected WebServiceClient wsc_;


    /**
     * Random password generation.
     * <p>
     * See http://stackoverflow.com/questions/41107/how-to-generate-a-random-alpha-numeric-string-in-java
     */
    protected static class PasswordGenerator {
        private SecureRandom random_ = new SecureRandom();

        /**
         * Return a randomly-chosen alphanumeric string with @a numBits of entropy.
         */
        public String randomPassword(int numBits) {
            // XXX: round `numBits` to nearest multiple of log2(32)
            return new BigInteger(numBits, random_).toString(32);
        }

        /**
         * Return a randomly-chosen alphanumeric string with 128 bits of entropy.
         */
        public String randomPassword() {
            return randomPassword(130);
        }
    }

    /**
     * Single instance of the PasswordGenerator.  Shared and used by all instances of this
     * class.
     */
    protected static final PasswordGenerator passwordGenerator_ = new PasswordGenerator();


    /**
     * Constructor, taking configuration parameters from a property list.
     * <p>
     * Same as calling {@link #SLCSFactory(Properties,boolean)} with {@code true}
     * as the second argument.  
     *
     * @param props Server-wide configuration parameters, used in the Shibboleth/SLCS negotiation; see {@link #SLCSFactory(Properties,boolean)} for a list of required property names.
     *
     * @throws org.opensaml.xml.ConfigurationException if bootstrapping the OpenSAML library did not succeed
     * @throws InitializationException wrapping the causing exception
     * @throws InvalidConfigurationException if any of the required properties (see above) is missing.
     *
     * @see #SLCSFactory(Properties,boolean)
     */
    public SLCSFactory(final Properties props) 
        throws InitializationException, InvalidConfigurationException
    {
        this(props,
             true);
    }


    /**
     * Constructor, taking configuration parameters from a property list.
     * <p>
     * The following properties are read off the {@code props}
     * parameter (prefix names with {@code gridcertlib.}:
     * <dl>
     * <dt>{@code slcsLoginUrl           }<dd>URL to the SLCS service login
     * <dt>{@code wspSessionInitiatorUrl }<dd>URL to the WSP Session Initiator (typically ends in `.../Shibboleth.sso/WSP`)
     * <dt>{@code providerId             }<dd>SP "entity Id" (must match the one in `/etc/shibboleth/shibboleth2.xml`)
     * <dt>{@code pemCertificatePath     }<dd>filesystem path to the SP SSL certificate (in PEM format)
     * <dt>{@code pemPrivateKeyPath      }<dd>filesystem path to the SP SSL private key (in PEM format)
     * <dt>{@code pemPrivateKeyPassword  }<dd>string used to decrypt the SSL private key (optional; if omitted, key needs no password)
     * <dt>{@code pemCACertificatesPath  }<dd>filesystem path to trusted CA certificates (all in a single PEM-format file)
     * <dt>{@code slcsStoreDirectory     }<dd>Filesystem path to a directory where the SLCS certificates and private keys will be saved (unless overridden in the {@link #newSLCS(String,String,String)} call).
     * <dt>{@code slcsPrivateKeySize     }<dd>Default size (in bits) of the requested private key.
     * </dl>
     * <p>
     * If second argument {@code doOpenSamlBootstrap} is {@code true},
     * then initialize the OpenSAML library by calling {@link
     * ch.SWITCH.aai.idwsf.xml.OpenSAML#bootstrap}.
     * <p>
     * On error, throws an {@link InitializationException} instance
     * wrapping the causing exception; this can be one of:<ul>
     * <li>{@link org.opensaml.xml.ConfigurationException} if bootstrapping the OpenSAML library did not succeed
     * <li>{@link java.security.GeneralSecurityException} when creating web service client for secure WSP access
     * <li>{@link java.io.IOException}  when creating web service client for secure WSP access
     * </ul>
     *
     * @param props                Server-wide configuration parameters, used in the Shibboleth/SLCS negotiation; see method description for the actual property names read.
     * @param doOpenSamlBootstrap  If {@code true}, initialize the OpenSAML library by calling {@link ch.SWITCH.aai.idwsf.xml.OpenSAML#bootstrap}
     *
     * @throws org.opensaml.xml.ConfigurationException if bootstrapping the OpenSAML library did not succeed
     * @throws InitializationException wrapping the causing exception
     * @throws InvalidConfigurationException if any of the required properties (see above) is missing.
     */
    public SLCSFactory(final Properties props, final boolean doOpenSamlBootstrap) 
        throws InitializationException, InvalidConfigurationException
    {
        // chain constructor
        this(getRequiredProperty(props, "gridcertlib.slcsLoginURL"),
             getRequiredProperty(props, "gridcertlib.wspSessionInitiatorURL"),
             getRequiredProperty(props, "gridcertlib.providerId"),
             getRequiredProperty(props, "gridcertlib.pemCertificatePath"),
             getRequiredProperty(props, "gridcertlib.pemPrivateKeyPath"),
             getRequiredProperty(props, "gridcertlib.pemCACertificatesPath"),
             props.getProperty("gridcertlib.pemPrivateKeyPassword", ""),
             props.getProperty("gridcertlib.slcsStoreDirectory", "/tmp"),
             Integer.parseInt(props.getProperty("gridcertlib.slcsPrivateKeySize", "1024")),
             doOpenSamlBootstrap);
    }

    protected static String getRequiredProperty(final Properties props, final String name)
        throws InvalidConfigurationException
    {
        String value = props.getProperty(name);
        if (null == value)
            throw new InvalidConfigurationException("Missing required property '" + name + "'");
        return value;
    }


    /**
     * Constructor, taking server-wide configuration parameters as explicit arguments.
     * <p>
     * On error, throws an {@link InitializationException} instance
     * wrapping the causing exception; this can be one of:<ul>
     * <li>{@link org.opensaml.xml.ConfigurationException} if bootstrapping the OpenSAML library did not succeed
     * <li>{@link java.security.GeneralSecurityException} when creating web service client for secure WSP access
     * <li>{@link java.io.IOException}  when creating web service client for secure WSP access
     * </ul>
     *
     * @param slcsLoginUrl           URL to the SLCS service login
     * @param wspSessionInitiatorUrl URL to the WSP Session Initiator (typically ends in `.../Shibboleth.sso/WSP`)
     * @param providerId             SP "entity Id" (must match the one in `/etc/shibboleth/shibboleth2.xml`)
     * @param pemCertificatePath     filesystem path to the SP SSL certificate (in PEM format)
     * @param pemPrivateKeyPath      filesystem path to the SP SSL private key (in PEM format)
     * @param pemPrivateKeyPassword  string used to decrypt the SSL private key
     * @param pemCACertificatesPath  filesystem path to trusted CA certificates (all in a single PEM-format file)
     * @param storeDirectory         Filesystem path to a directory where the SLCS certificates and private keys will be saved by default.
     * @param defaultPrivateKeySize  Default size (in bits) of the requested private key.
     * @param doOpenSamlBootstrap    If {@code true}, initialize the OpenSAML library by calling {@link ch.SWITCH.aai.idwsf.xml.OpenSAML#bootstrap}
     *
     * @throws InitializationException wrapping the causing exception
     */
    public SLCSFactory(final String slcsLoginUrl,
                       final String wspSessionInitiatorUrl,
                       final String providerId,
                       final String pemCertificatePath,
                       final String pemPrivateKeyPath,
                       final String pemCACertificatesPath,
                       final String pemPrivateKeyPassword,
                       final String storeDirectory,
                       final int defaultPrivateKeySize,
                       final boolean doOpenSamlBootstrap) 
        throws InitializationException
    {
        assert(null != slcsLoginUrl);
        assert(null != wspSessionInitiatorUrl);
        assert(null != providerId);
        assert(null != pemCertificatePath);
        assert(null != pemPrivateKeyPath);
        assert(null != pemPrivateKeyPassword);
        assert(null != pemCACertificatesPath);
        assert(null != storeDirectory);

        slcsLoginUrl_ = slcsLoginUrl;                      LOG.debug("SLCSFactory: initialized with slcsLoginUrl='" + slcsLoginUrl + "'");
        wspSessionInitiatorUrl_ = wspSessionInitiatorUrl;  LOG.debug("SLCSFactory: initialized with wspSessionInitiatorUrl='" + wspSessionInitiatorUrl + "'");
        defaultStoreDirectory_ = storeDirectory;           LOG.debug("SLCSFactory: initialized with storeDirectory='" + storeDirectory + "'");
        defaultPrivateKeySize_ = defaultPrivateKeySize;    LOG.debug("SLCSFactory: initialized with defaultPrivateKeySize='" + defaultPrivateKeySize + "'");
        // create WebServiceClient; will be re-used by all `SLCSRequestor` instances
        LOG.debug("SLCSFactory: creating WebServiceClient with pemCertificatePath='" + pemCertificatePath + "'");
        LOG.debug("SLCSFactory: creating WebServiceClient with pemPrivateKeyPath='" + pemPrivateKeyPath + "'");
        LOG.debug("SLCSFactory: creating WebServiceClient with pemPrivateKeyPassword='" + pemPrivateKeyPassword + "'");
        LOG.debug("SLCSFactory: creating WebServiceClient with pemCACertificatesPath='" + pemCACertificatesPath + "'");

        try {
            wsc_ = new WebServiceClient(providerId,
                                        new PEMTLSCredentials(pemCertificatePath,
                                                              pemPrivateKeyPath,
                                                              pemPrivateKeyPassword,
                                                              pemCACertificatesPath));
        }
        catch(java.security.GeneralSecurityException x) {
            throw new InitializationException("Failed creating WebServiceClient (GeneralSecurityException): " 
                                              + x.getMessage(), x);
        }
        catch(java.io.IOException x) {
            throw new InitializationException("Failed creating WebServiceClient (IOException): " 
                                              + x.getMessage(), x);
        };

        try {
            // bootstrapping OpenSAML libraries is needed by Valery's IDWSF-ECP lib
            if (doOpenSamlBootstrap) {
                LOG.debug("SLCSFactory: performing OpenSAML bootstrap...");
                OpenSAML.bootstrap();
            };
        }
        catch(org.opensaml.xml.ConfigurationException x) {
            throw new InitializationException("Failed bootstrapping OpenSAML library: " 
                                              + x.getMessage(), x);
        };
    }


    /**
     * Generate a new SLCS certificate and store it in the default
     * store directory; also, encrypt the private key with a random
     * password.
     * <p>
     * See {@link #newSLCS(String,String,String,String)} for details.
     *
     * @param samlAssertionUrl  URL of the SAML2 Assertion provided by the Shibboleth IdP; this is generally available from HTTP header {@code Shib-Assertion-01}
     *
     * @see #newSLCS(String,String,String,String)
     */
    public CredentialsPathInfo newSLCS(final String samlAssertionUrl)
        throws OperationsError
    {
        final String unique = passwordGenerator_.randomPassword();
        final String certificatePath = getStoreDirectory() + File.separator + "cert-" + unique + ".pem";
        final String privateKeyPath = getStoreDirectory() + File.separator + "key-" + unique + ".pem";

        return newSLCS(samlAssertionUrl,
                certificatePath,
                privateKeyPath,
                passwordGenerator_.randomPassword());
    }


    /**
     * Generate a new SLCS certificate, encrypting the private key with a random password.
     * <p>
     * See {@link #newSLCS(String,String,String,String)} for details.
     *
     * @param samlAssertionUrl  URL of the SAML2 Assertion provided by the Shibboleth IdP; this is generally available from HTTP header {@code Shib-Assertion-01}
     * @param certificatePath   Path to a file where the SLCS public certificate will be stored
     * @param privateKeyPath    Path to a file where the SLCS private key will be stored
     *
     * @see #newSLCS(String,String,String,String)
     */
    public CredentialsPathInfo newSLCS(final String samlAssertionUrl,
                                       final String certificatePath,
                                       final String privateKeyPath)
        throws OperationsError
    {
        return newSLCS(samlAssertionUrl,
                certificatePath,
                privateKeyPath,
                passwordGenerator_.randomPassword());
    }


    /**
     * Generate a new SLCS certificate and save its public and
     * private keys in the given files.
     *
     * @param samlAssertionUrl   URL of the SAML2 Assertion provided by the Shibboleth IdP; this is generally available from HTTP header {@code Shib-Assertion-01}
     * @param certificatePath    Path to a file where the SLCS public certificate will be stored
     * @param privateKeyPath     Path to a file where the SLCS private key will be stored
     * @param privateKeyPassword Password to use to encrypt the SLCS private key
     *
     * @see #newSLCS(String,String,String,String)
     */
    public CredentialsPathInfo newSLCS(final String samlAssertionUrl,
                                       final String certificatePath,
                                       final String privateKeyPath,
                                       final String privateKeyPassword)
        throws OperationsError
    {
        SLCSRequestor slcs;
        try {
            slcs = new SLCSRequestor(wsc_, samlAssertionUrl, 
                                     wspSessionInitiatorUrl_, slcsLoginUrl_);
            slcs.performSlcsInit(privateKeyPassword);
        }
        // re-throw various exceptions wrapped into an `OperationsError`
        catch (SLCSException x) {
            throw new OperationsError("Error performing SLCS operations "
                                      + "(SLCSException): " + x.getMessage(), x);
        }
        catch (TokenResolverException x) {
            throw new OperationsError("Error performing SLCS operations "
                                      + "(TokenResolverException): " + x.getMessage(), x);
        }
        catch (GeneralSecurityException x) {
            throw new OperationsError("Error performing SLCS operations "
                                      + "(GeneralSecurityException): " + x.getMessage(), x);
        }
        catch (IOException x) {
            throw new OperationsError("Error performing SLCS operations "
                                      + "(IOException): " + x.getMessage(), x);
        };

        try {
            storeCertificate(slcs, certificatePath);
        }
        catch (IOException x) {
            throw new OperationsError("Got IOException while saving certificate to file '"
                                      + certificatePath +
                                      "': " + x.getMessage(), x);
        };

        try {
            storePrivateKey(slcs, privateKeyPath);
        }
        catch (IOException x) {
            throw new OperationsError("Got IOException while saving private key to file '"
                                      + privateKeyPath +
                                      "': " + x.getMessage(), x);
        };

        return new CredentialsPathInfo(certificatePath, privateKeyPath, privateKeyPassword);
    }

    /**
     * Store the private key (userkey.pem) in the store directory.
     *
     * @throws java.io.IOException If an error occurs while writing the userkey.pem file.
     */
    protected void storePrivateKey(final SLCSRequestor slcs, final String filename)
            throws IOException 
    {
        File file = new File(filename);
        backupFile(file);
        LOG.info("Storing private key into: " + filename);
        slcs.getCertificateKeys().storePEMPrivate(file);
    }

    /**
     * Stores the X509 certificate with its chain (usercert.pem) in the store
     * directory.
     *
     * @param slcs     Requestor object
     * @param filename File Name to write to
     * @throws java.io.IOException If an error occurs while writing the usercert.pem file.
     */
    protected void storeCertificate(final SLCSRequestor slcs, final String filename)
            throws IOException 
    {
        File file = new File(filename);
        backupFile(file);
        LOG.info("Storing certificate into: " + filename);
        slcs.getCertificate().storePEM(file);
    }

    /**
     * Backup the given file using a rotating backup scheme: filename.1 ..
     * filename.2 ...
     *
     * @param file The file to rotate
     */
    protected void backupFile(File file) {
        if (file.exists() && file.isFile()) {
            String filename = file.getAbsolutePath();
            // delete the oldest file, for Windows
            String backupFilename = filename + "." + MAX_BACKUP;
            File backupFile = new File(backupFilename);
            if (backupFile.exists() && backupFile.isFile()) {
                LOG.debug("delete old " + backupFile);
                backupFile.delete();
            }
            // rotate backup files:[MAX_BACKUP-1..1]
            for (int i = MAX_BACKUP - 1; i >= 1; i--) {
                backupFilename = filename + "." + i;
                backupFile = new File(backupFilename);
                if (backupFile.exists() && backupFile.isFile()) {
                    String targetFilename = filename + "." + (i + 1);
                    File targetFile = new File(targetFilename);
                    LOG.info("Rotate backup file: " + backupFile + " -> "
                            + targetFile);
                    backupFile.renameTo(targetFile);
                }
            }

            // backup filename to filename.1
            LOG.info("Backup file: " + file + " -> " + backupFile);
            file.renameTo(backupFile);

        }
    }

    /**
     * Creates if necessary and returns the absolute directory name.
     *
     * @return The absolute directory name to store the usercert.pem and
     *         userkey.pem files.
     */
    public String getStoreDirectory() {
        File dir = new File(defaultStoreDirectory_);
        // BUG FIX: create dir if not exist
        if (!dir.exists()) {
            LOG.info("create store directory: " + dir.getAbsolutePath());
            dir.mkdirs();
        }
        return dir.getAbsolutePath();
    }

    /**
     * Sets the absolute pathname to the store directory and creates it if
     * necessary.
     *
     * @param directory The absolute pathname of the store directory.
     * @return <code>true</code> iff the absolute dirname is an existing
     *         writable directory
     */
    public boolean setStoreDirectory(final String directory) {
        boolean valid = false;
        if (directory == null) {
            return false;
        }
        File dir = new File(directory);
        // BUG FIX: create dir if not exist
        if (!dir.exists()) {
            LOG.info("create store directory: " + dir.getAbsolutePath());
            dir.mkdirs();
        }
        if (dir.isDirectory() && dir.canWrite()) {
            defaultStoreDirectory_ = dir.getAbsolutePath();
            valid = true;
        } else {
            LOG.error("Not a valid store directory: " + directory);
        }
        return valid;
    }
}