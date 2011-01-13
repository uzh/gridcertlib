/**
 * @file   GridProxyFactory.java
 * @author riccardo.murri@gmail.com
 *
 * Source code for class GridProxyFactory
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

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.glite.voms.contact.VOMSProxyInit;
import org.glite.voms.contact.VOMSProxyBuilder;
import org.glite.voms.contact.UserCredentials;
import org.glite.voms.contact.VOMSProxyConstants;
import org.glite.voms.contact.VOMSRequestOptions;


/** 
 * Façade to create Globus Toolkit proxy certificates and store them
 * to a temporary location on the filesystem, optionally requiring
 * VOMS extensions.
 * <p>
 * A single instance of the class can generate multiple proxies
 * (possibly for different users) via repeated invocation of the 
 * {@link #newProxy(CredentialsPathInfo,String[])} method. 
 * <p>
 * Since the {@link org.glite.voms.contact.VOMSProxyInit} class uses
 * system properties to determine part of its configuration (see
 * below), it is not possible to create different instances of this
 * class, each using its own configuration.  This will not be a limit
 * in practice, as the {@code org.glite.voms} library has native
 * support for multiple servers and VO endpoints.
 * <p>
 * <em>Note:</em> the {@link org.glite.voms.contact.VOMSProxyInit}
 * class reads some parameters from the following Java System
 * properties:
 * <dl>
 * <dt>{@code VOMSES_LOCATION }<dd>Directory where voms specification files are located (colon separated list of directories). Defaults to {@code $GLITE_LOCATION/etc/vomses}.
 * <dt>{@code VOMSDIR         }<dd>Directory where voms certificates are located. Defaults to {@code /etc/grid-security/vomsdir}
 * <dt>{@code CADIR           }<dd>Directory where CA certificates are stored; usual default is {@code /etc/grid-security/certificates}
 * </dl>
 * Since System Properties cannot be set programmatically, it is the
 * deployer's responsibility to ensure that these parameters are set
 * to a correct value.
 */
public class GridProxyFactory {

    /** Logging */
    static Logger LOG = LoggerFactory.getLogger(GridProxyFactory.class);


    /**
     * Lifetime of the generated proxy and VOMS ACs, in seconds
     * (Default: {@link org.glite.voms.contact.VOMSProxyBuilder.DEFAULT_LIFETIME}).  
     * If the requested lifetime of an AC is larger than the maximum
     * accepted by the VOMS server, it will be silently shortened.
     */
    protected int lifetime_;


    /** Set lifetime of the proxy to be generated. */
    public void setLifetime(int lifetime) 
    { 
        if (lifetime < 0)
            throw new IllegalArgumentException("Proxy lifetime must be a positive integer,"
                                               + " but got " + lifetime + " instead.");
        lifetime_ = lifetime; 
    }


    /**
     * Proxy type of the generated proxy (GT2, GT3, or GT4/RFC3820).
     * See http://dev.globus.org/wiki/Security/ProxyCertTypes for an explanation
     * of the different types.
     * Default is to use {@link org.glite.voms.contact.VOMSProxyBuilder.DEFAULT_PROXY_TYPE}.
     */
    protected int proxyType_;

    /** Set type of the proxy to be generated.  See
     * http://dev.globus.org/wiki/Security/ProxyCertTypes for an
     * explanation of the different types.
     * 
     * @see GridProxyType
     */
    public void setProxyType(GridProxyType T) 
    {
        proxyType_ = T.proxyType();
    }


    /**
     * Constructor taking the configuration as a properties object.
     * The following properties set the configuration:
     * <dl>
     * <dt>{@code gridcertlib.proxy.lifetime }<dd>Lifetime of the proxy, in seconds. Must be a positive integer.
     * <dt>{@code gridcertlib.proxy.type     }<dd>Type of the proxy to create: one of the strings "GT2", "GT3" or "GT4"
     * </dl>
     * If a property is not present, default values are used instead;
     * see {@link #lifetime_}, {@link #proxyType_}.  
     * <p>
     * If a property has an invalid value (e.g.,
     * {@code gridcertlib.proxy.lifetime} cannot be converted to a positive
     * integer), then IllegalArgumentException is thrown.
     *
     * @param props properties object with the necessary configuration.
     *
     * @throws IllegalArgumentException if one of the configuration properties has an invalid value
     *
     * @see #lifetime_
     * @see #proxyType_
     * @see org.glite.voms.contact.VOMSProxyBuilder
     */
    public GridProxyFactory(Properties props) 
    {
        String lifetimeProp = props.getProperty("gridcertlib.proxy.lifetime");
        if (null == lifetimeProp)
            lifetime_ = VOMSProxyBuilder.DEFAULT_PROXY_LIFETIME;
        else
            lifetime_ = Integer.parseInt(lifetimeProp);
        if (lifetime_ < 0)
            throw new IllegalArgumentException("Bad value '" + lifetimeProp
                                               + "' for property 'gridcertlib.proxy.lifetime':"
                                               + " must be a positive integer.");

        String typeProp = props.getProperty("gridcertlib.proxy.type");
        if (null == typeProp)
            proxyType_ =  VOMSProxyBuilder.DEFAULT_PROXY_TYPE;
        else {
            typeProp = typeProp.trim();
            if (typeProp.equalsIgnoreCase("GT2")) 
                proxyType_ = VOMSProxyBuilder.GT2_PROXY;
            else if (typeProp.equalsIgnoreCase("GT3")) 
                proxyType_ = VOMSProxyBuilder.GT3_PROXY;
            else if (typeProp.equalsIgnoreCase("GT4") 
                 || typeProp.equalsIgnoreCase("RFC3820")) 
                proxyType_ = VOMSProxyBuilder.GT4_PROXY;
            else throw new IllegalArgumentException("Bad value '" + typeProp 
                                                + "' for property 'gridcertlib.proxy.type':"
                                                + " must be one of 'GT2', 'GT3', or 'GT4'.");
        }
    }


    /**
     * Generate a new proxy (without VOMS extensions), store it in a temporary file and return its path.
     * See {@link #newProxy(String,String,String,String[])} for more information.
     *
     * @param x509creds {@link CredentialsPathInfo} instance, pointing to an X.509 certificate/private key pair and password.
     *
     * @return full path of the created proxy
     *
     * @see #newProxy(String,String,String,String[])
     */

    public String newProxy(final CredentialsPathInfo x509creds)
        throws IOException 
    {
        return newProxy(x509creds.getCertificatePath(),
                        x509creds.getPrivateKeyPath(),
                        x509creds.getPrivateKeyPassword(),
                        null);
    }

    /**
     * Generate a new proxy with VOMS extensions, store it in a temporary file and return its path.
     * See {@link #newProxy(String,String,String,String[])} for more information.
     *
     * @param x509creds {@link CredentialsPathInfo} instance, pointing to an X.509 certificate/private key pair and password.
     * @param vo        VO name; the relevant VOMS server will be contacted for getting the AC
     *
     * @return full path of the created proxy
     *
     * @see #newProxy(String,String,String,String[])
     */

    public String newProxy(final CredentialsPathInfo x509creds,
                           final String vo)
        throws IOException {
        return newProxy(x509creds.getCertificatePath(),
                        x509creds.getPrivateKeyPath(),
                        x509creds.getPrivateKeyPassword(),
                        new String[]{vo});
    }


    /**
     * Generate a new proxy with VOMS extensions, store it in a temporary file and return its path.
     * See {@link #newProxy(String,String,String,String[])} for more information.
     *
     * @param x509creds {@link CredentialsPathInfo} instance, pointing to an X.509 certificate/private key pair and password.
     * @param vomsArgs  list of VOMS commands in the form {@code <voms>}[:{@code <command>}] (identical to "-voms" arguments of the {@code glite-voms-proxy-init} command). If {@code null}, then a non-VOMS proxy is created.
     *
     * @return full path of the created proxy
     *
     * @see #newProxy(String,String,String,String[])
     */

    public String newProxy(final CredentialsPathInfo x509creds,
                           final String[] vomsArgs)
        throws IOException 
    {
        return newProxy(x509creds.getCertificatePath(),
                        x509creds.getPrivateKeyPath(),
                        x509creds.getPrivateKeyPassword(),
                        vomsArgs);
    }


    /**
     * Generate a new proxy with VOMS extensions, store it in a
     * temporary file and return its path.  The temporary file is
     * deleted as soon as the JVM exists: if you need to store the
     * proxy in a persistent way, copy its contents.
     * <p>
     * This method is {@code synchronized} as the VOMS Java API (as of version 1.9.x)
     * implements the {@code VOMSProxyInit} class as a singleton.
     * <p>
     * <em>Note:</em> the {@link org.glite.voms.contact.VOMSProxyInit}
     * class reads some parameters from the following Java System
     * properties:
     * <dl>
     * <dt>{@code VOMSES_LOCATION }<dd>Directory where voms specification files are located (colon separated list of directories). Defaults to {@code $GLITE_LOCATION/etc/vomses}.
     * <dt>{@code VOMSDIR         }<dd>Directory where voms certificates are located. Defaults to {@code /etc/grid-security/vomsdir}
     * <dt>{@code CADIR           }<dd>Directory where CA certificates are stored; usual default is {@code /etc/grid-security/certificates}
     * </dl>
     * Since System Properties cannot be set programmatically, it is the
     * deployer's responsibility to ensure that these parameters are set
     * to a correct value.
     *
     * @param certificatePath    filename path to the X.509 certificate (public key)
     * @param privateKeyPath     filename path to the X.509 private key
     * @param privateKeyPassword the password to use for decrypting the certificate key
     * @param vomsArgs  list of VOMS commands in the form {@code <voms>}[:{@code <command>}] (identical to "-voms" arguments of the {@code glite-voms-proxy-init} command). If {@code null}, then a non-VOMS proxy is created.
     *
     * @return full path of the created proxy
     */
    public synchronized String newProxy(final String certificatePath,
                                        final String privateKeyPath,
                                        final String privateKeyPassword,
                                        final String[] vomsArgs)
        throws IOException 
    {
        // generate a random file name; it will be deleted when
        // the Java VM exits
        File tempFile = File.createTempFile("proxy", ".pem");
        tempFile.deleteOnExit();
        String proxyPath = tempFile.getAbsolutePath();

        // parts of the following code were adapted from the jLite library,
        // see http://code.google.com/p/jlite/
        UserCredentials userCredentials = UserCredentials.instance(certificatePath, privateKeyPath, privateKeyPassword);
        VOMSProxyInit vomsProxyInit = VOMSProxyInit.instance(userCredentials);
        vomsProxyInit.setProxyLifetime(lifetime_);
        vomsProxyInit.setProxyOutputFile(proxyPath);
        vomsProxyInit.setProxyType(proxyType_);
        vomsProxyInit.setDelegationType(VOMSProxyConstants.DELEGATION_FULL); // there's no use for limited proxies in a portal

        if (null != vomsArgs) {
            Map<String, VOMSRequestOptions> optionsByVo = new HashMap<String, VOMSRequestOptions>();
            for (String vomsArg : vomsArgs) {
                String vo = vomsArg;
                String fqan = null;
                if (vomsArg.indexOf(":") > 0) {
                    String[] parts = vomsArg.split(":");
                    vo = parts[0];
                    fqan = parts[1];
                }
                VOMSRequestOptions options;
                if (optionsByVo.containsKey(vo)) {
                    options = optionsByVo.get(vo);
                } else { // no other FQANs for this VO
                    options = new VOMSRequestOptions();
                    options.setVoName(vo);
                    options.setLifetime(lifetime_);
                }
                if (fqan != null) {
                    options.addFQAN(fqan);
                    LOG.debug("Will request FQAN '" + fqan + "' for VO '" + vo + "'");
                }
                optionsByVo.put(vo, options);
            };
            // finally, call into voms-proxy-init
            vomsProxyInit.getVomsProxy(optionsByVo.values());
        }
        else // vomsArgs == null
            vomsProxyInit.getVomsProxy(null);
            
        return proxyPath;
    }

}

