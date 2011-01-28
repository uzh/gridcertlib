/**
 * @file SLCSRequestor.java
 * @author peter.kunszt@systemsx.ch, riccardo.murri@gmail.com, valery.tschopp@switch.ch
 *
 * Source code for class SLCSRequestor; part of this code imported
 * originally from the {@link org.glite.slcs.ui} package.
 *
 */
/* 
 * Copyright (c) 2010, ETH Zurich and University of Zurich.  All rights reserved.
 * 
 * This file is part of the GriCertLib software project.
 * You may copy, distribute and modify this file under the terms of
 * the LICENSE.txt file at the root of the project directory tree.
 *
 * $Id$
 */

package ch.swing.gridcertlib;

import ch.SWITCH.aai.idwsf.ecp.DelegationContext;
import ch.SWITCH.aai.idwsf.ecp.DelegationException;
import ch.SWITCH.aai.idwsf.ecp.ECPException;
import ch.SWITCH.aai.idwsf.ecp.WebServiceClient;
import ch.SWITCH.aai.idwsf.token.SAML2AssertionURLResolver;
import ch.SWITCH.aai.idwsf.token.TokenResolverException;
import ch.SWITCH.httpclient.tls.PEMTLSCredentials;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.opensaml.saml2.core.Assertion;
import org.glite.slcs.AuthException;
import org.glite.slcs.SLCSException;
import org.glite.slcs.ServiceException;
import org.glite.slcs.jericho.html.Element;
import org.glite.slcs.jericho.html.Source;
import org.glite.slcs.pki.CertificateExtension;
import org.glite.slcs.pki.CertificateExtensionFactory;
import org.glite.slcs.pki.CertificateKeys;
import org.glite.slcs.pki.CertificateRequest;
import org.glite.slcs.pki.Certificate;
import org.glite.slcs.pki.bouncycastle.Codec;

import org.joda.time.DateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


/**
 * Utility class to perform all steps to generate a SLCS certificate.
 * <p>
 * Methods in this class cover all steps of the procedure to obtain a
 * SLCS certificate.
 * <p>
 * Example usage: <code>
 * SCLSRequestor slcs = new SLCSRequestor(samlAssertionUrl);
 * slcs.login();
 * slcs.generateCertificateKeys(password);
 * slcs.generateCertificateRequest();
 * slcs.requestSlcsCertificate();
 * </code>
 * The {@link #performSlcsInit} method is provided to perform all of the above in one go.
 */
class SLCSRequestor {

    /**
     * Logging
     */
    static Logger LOG = LoggerFactory.getLogger(SLCSRequestor.class);
    /**
     * Default number of backup file to keep
     */
    static int MAX_BACKUP = 3;
    /**
     * Delegation Context
     */
    private DelegationContext context_ = null;
    /**
     * Web Service Client
     */
    private WebServiceClient wsc_ = null;
    /**
     * Authorization Token
     */
    private String authorizationToken_ = null;
    /**
     * URL to post certificate requests
     */
    private String certificateRequestUrl_ = null;
    /**
     * Certificate subject
     */
    private String certificateSubject_ = null;
    /**
     * List of required certificate extensions
     */
    private List<CertificateExtension> certificateExtensions_ = null;
    /**
     * Private key size
     */
    private int keySize_ = 1024;
    /**
     * Private and public keys
     */
    private CertificateKeys certificateKeys_ = null;
    /**
     * Certificate request
     */
    private CertificateRequest certificateRequest_ = null;
    /**
     * X.509 certificate
     */
    private Certificate certificate_ = null;

    /**
     * SLCS service login URL
     */
    private final String slcsLoginUrl_;


    /**
     * Constructor, taking the SAML assertion URL and a properties
     * object with server-wide configuration parameters.
     * <p>
     * The resulting SLCSRequestor instance will be functional as long
     * as the SAML assertion pointed by {@code assertionUrl} is valid.
     *
     * @param wsc                    A {@link ch.SWITCH.aai.idwsf.ecp.WebServiceClient} instance to use for Shibboleth/HTTP negotiations
     * @param assertionUrl URL to the SAML assertion resulting from the Shibboleth login process.
     * @param wspSessionInitiatorUrl URL to the WSP Session Initiator (typically ends in `.../Shibboleth.sso/WSP`)
     * @param slcsLoginUrl           URL to the SLCS service login
     *
     */
    public SLCSRequestor(final WebServiceClient wsc,
                         final String assertionUrl,
                         final String wspSessionInitiatorUrl,
                         final String slcsLoginUrl)
        throws GeneralSecurityException, IOException, TokenResolverException, AssertionExpiredError
    {
        // get the delegated client through the idwsf library
        SAML2AssertionURLResolver resolver = new SAML2AssertionURLResolver(assertionUrl);
        Assertion assertion;
        try {
            assertion = resolver.resolveToken();
        }
        catch (ch.SWITCH.aai.idwsf.token.AssertionException x) {
            // XXX: are there other cases where `AssertionException` can be thrown?
           throw new AssertionExpiredError("Assertion expired, please log out and then in again");
        }
        LOG.debug("SLCSRequestor: retrieved assertion ID: " 
                  + assertion.getID());
        LOG.debug("SLCSRequestor: retrieved assertion for subject: " 
                  + assertion.getSubject().getNameID().getValue());
        LOG.debug("SLCSRequestor: retrieved assertion issued by: " 
                  + assertion.getIssuer().getValue());
        LOG.debug("SLCSRequestor: retrieved assertion is valid until: " 
                  + assertion.getConditions().getNotOnOrAfter().toLocalDateTime().toString());
        // create the delegation context
        DelegationContext context = new DelegationContext(assertion);
        // set the WSP session initiator URL
        LOG.debug("SLCSRequestor: using WSP session initiator URL '" + wspSessionInitiatorUrl + "'");
        context.setWSPSessionIntiatorURL(wspSessionInitiatorUrl);
        setContext(context);
        setWsc(wsc);
        // remember the SLCS login URL for use in `login()`
        slcsLoginUrl_ = slcsLoginUrl;
    }


    /**
     * Constructor, taking the SAML assertion URL and a properties object with server-wide configuration parameters.
     * <p>
     * The resulting SLCSRequestor instance will be functional as long
     * as the SAML assertion pointed by {@code assertionUrl} is valid.
     * <p>
     * Some server-wide configuration parameters are necessary for the
     * Shibboleth negotiation over HTTP.  These are provided by the
     * {@code props} parameter.  The following properties are read off
     * the {@code props} object (prefix names with {@code gridcertlib.}):
     * <dl>
     * <dt>slcsLoginURL           <dd>URL to the SLCS service login
     * <dt>wspSessionInitiatorURL <dd>URL to the WSP Session Initiator (typically ends with `.../Shibboleth.sso/WSP`)
     * </dl>
     *
     * @param wsc                    A {@link ch.SWITCH.aai.idwsf.ecp.WebServiceClient} instance to use for Shibboleth/HTTP negotiations
     * @param assertionUrl URL to the SAML assertion resulting from the Shibboleth login process.
     * @param props        properties used in the Shibbolethised negotiation: SP ID, server X.509 certificate paths, etc.
     *
     * @throw InvalidConfigurationException if any of the required properties (see above) is missing.
     */
    public SLCSRequestor(final WebServiceClient wsc,
                         final String assertionUrl,
                         final Properties props) 
        throws InvalidConfigurationException, GeneralSecurityException, IOException, TokenResolverException 
    {
        this(wsc, assertionUrl,
             getRequiredProperty(props, "gridcertlib.wspSessionInitiatorURL"),
             getRequiredProperty(props, "gridcertlib.slcsLoginURL"));
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
     * Carry out the full SLCS negotiation in one go.
     * <p>
     * If successful, the certificate and private key can be
     * retrieved using the {@link #getCertificate()} and
     * {@link #getPrivateKey()} methods.
     *
     * @param password
     * @throws java.security.GeneralSecurityException
     *
     * @throws org.glite.slcs.SLCSException
     */
    public void performSlcsInit(final String password) 
        throws SLCSException, GeneralSecurityException 
    {
        login();
        generateCertificateKeys(password.toCharArray());
        generateCertificateRequest();
        requestSlcsCertificate();
    }


    /**
     * Login to the SLCS service.
     * <p>
     * As a side effect, fills the {@code certificateRequestUrl_},
     * {@code certificateSubject_}, and {@code certificateExtensions_}
     * member variables.
     */
    public void login()
            throws SLCSException {
        GetMethod getLoginMethod = new GetMethod(slcsLoginUrl_);
        try {
            LOG.info("GET login: " + slcsLoginUrl_);
            int status = wsc_.executeMethod(context_, getLoginMethod);
            LOG.debug(getLoginMethod.getStatusLine().toString());
            // XXX: do we need to handle 30x (redirect) codes?
            if (status != 200) {
                LOG.error("SLCS login failed: "
                        + getLoginMethod.getStatusLine());
                if (status == 401) {
                    throw new AuthException("SLCS authorization failed: "
                            + getLoginMethod.getStatusLine() + ": "
                            + slcsLoginUrl_);
                } else {
                    throw new AuthException("SLCS login failed: "
                            + getLoginMethod.getStatusLine());

                }
            }
            // read response
            InputStream is = getLoginMethod.getResponseBodyAsStream();
            Source source = new Source(is);
            checkSLCSResponse(source, "SLCSLoginResponse");
            parseSLCSLoginResponse(source);
        } catch (IOException e) {
            final String message = "Failed to request DN: " + e.getMessage();
            LOG.error(message, e);
            throw new SLCSException(message, e);
        } catch (ECPException e) {
            final String message = "SLCS login failed, ECP error: " + e.getMessage();
            LOG.error(message, e);
            throw new SLCSException(message, e);
        } catch (DelegationException e) {
            final String message = "SLCS login failed, delegation error: " + e.getMessage();
            LOG.error(message, e);
            throw new SLCSException(message, e);
        } finally {
            getLoginMethod.releaseConnection();
        }
    }

    /**
     * Check the return status in an SLCS transaction.
     *
     * @param source The XML document outputted as the result of a SLCS HTTP method invocation
     * @param name   name of the XML element that contains the status/error elements
     */
    private void checkSLCSResponse(Source source, String name)
            throws IOException, SLCSException {
        // optimization !?!
        source.fullSequentialParse();

        int pos = 0;
        Element reponseElement = source.findNextElement(pos, name);
        if (reponseElement == null || reponseElement.isEmpty()) {
            LOG.error(name + " element not found");
            throw new ServiceException(name
                    + " element not found in SLCS response");
        }
        // read status
        Element statusElement = source.findNextElement(pos, "status");
        if (statusElement == null || statusElement.isEmpty()) {
            LOG.error("Status element not found");
            throw new ServiceException(
                    "Status element not found in SLCS response");
        }
        String status = statusElement.getContent().toString();
        LOG.info("Status=" + status);
        if (status != null && status.equalsIgnoreCase("Error")) {
            pos = statusElement.getEnd();
            Element errorElement = source.findNextElement(pos, "error");
            if (errorElement == null || errorElement.isEmpty()) {
                LOG.error("Error element not found");
                throw new SLCSException(
                        "Error element not found in SLCS error response");
            }
            String error = errorElement.getContent().toString();
            // is there a stack trace?
            pos = errorElement.getEnd();
            Element traceElement = source.findNextElement(pos, "stacktrace");
            if (traceElement != null && !traceElement.isEmpty()) {
                String stackTrace = traceElement.getContent().toString();
                throw new ServiceException(error + "\nRemote error:\n"
                        + stackTrace);
            }
            throw new ServiceException(error);
        } else if (status == null || !status.equalsIgnoreCase("Success")) {
            LOG.error("Unknown Status: " + status);
            throw new ServiceException("Unknown Status:" + status);
        }
    }

    /**
     * Auxiliary method to {@code slcsLogin}.
     * <p>
     * Fills the {@code authorizationToken_}, {@code certificateRequestUrl_},
     * {@code certificateSubject_}, and {@code certificateExtensions_}
     * member variables.
     */
    private void parseSLCSLoginResponse(Source source) throws SLCSException {
        // get AuthorizationToken
        int pos = 0;
        Element tokenElement = source.findNextElement(pos, "AuthorizationToken");
        if (tokenElement == null || tokenElement.isEmpty()) {
            LOG.error("AuthorizationToken element not found");
            throw new SLCSException(
                    "AuthorizationToken element not found in SLCS response");
        }
        authorizationToken_ = tokenElement.getContent().toString();
        LOG.info("AuthorizationToken=" + authorizationToken_);
        // get the certificate request URL
        pos = tokenElement.getEnd();
        Element certificateRequestElement = source.findNextElement(pos,
                "CertificateRequest");
        if (certificateRequestElement == null
                || certificateRequestElement.isEmpty()) {
            LOG.error("CertificateRequest element not found");
            throw new SLCSException(
                    "CertificateRequest element not found in SLCS response");
        }
        certificateRequestUrl_ = certificateRequestElement.getAttributeValue("url");
        if (certificateRequestUrl_ == null) {
            LOG.error("CertificateRequest url attribute not found");
            throw new SLCSException(
                    "CertificateRequest url attribute not found in SLCS response");
        } else if (!certificateRequestUrl_.startsWith("http")) {
            LOG.error("CertificateRequest url attribute doesn't starts with http: "
                    + certificateRequestUrl_);
            throw new SLCSException(
                    "CertificateRequest url attribute is not valid: "
                            + certificateRequestUrl_);
        }
        LOG.info("CertificateRequest url=" + certificateRequestUrl_);

        // get certificate subject
        Element subjectElement = source.findNextElement(pos, "Subject");
        if (subjectElement == null || subjectElement.isEmpty()) {
            LOG.error("Subject element not found");
            throw new SLCSException(
                    "Subject element not found in SLCS response");
        }
        certificateSubject_ = subjectElement.getContent().toString();
        LOG.info("CertificateRequest.Subject=" + certificateSubject_);
        // any certificate extensions?
        certificateExtensions_ = new ArrayList<CertificateExtension>();
        pos = subjectElement.getEnd();
        Element extensionElement = null;
        while ((extensionElement = source.findNextElement(pos,
                "certificateextension")) != null) {
            pos = extensionElement.getEnd();
            String extensionName = extensionElement.getAttributeValue("name");
            String extensionValues = extensionElement.getContent().toString();
            LOG.info("CertificateRequest.CertificateExtension: "
                    + extensionName + "=" + extensionValues);
            CertificateExtension extension = CertificateExtensionFactory.createCertificateExtension(
                    extensionName,
                    extensionValues);
            if (extension != null) {
                certificateExtensions_.add(extension);
            }
        }
    }


    /**
     * Request a certificate from the SLCS service and store the returned one.
     *
     * @throws org.glite.slcs.SLCSException
     */
    public void requestSlcsCertificate() throws SLCSException {
        PostMethod postCertificateRequestMethod = new PostMethod(
                certificateRequestUrl_);
        postCertificateRequestMethod.addParameter("AuthorizationToken",
                authorizationToken_);
        postCertificateRequestMethod.addParameter(
                "CertificateSigningRequest",
                certificateRequest_.getPEMEncoded());
        try {
            LOG.info("POST CSR: " + certificateRequestUrl_);
            int status = wsc_.executeMethod(postCertificateRequestMethod);
            LOG.debug(postCertificateRequestMethod.getStatusLine().toString());
            // check status
            if (status != 200) {
                LOG.error("SLCS certificate request failed: "
                        + postCertificateRequestMethod.getStatusLine());
                throw new ServiceException("SLCS certificate request failed: "
                        + postCertificateRequestMethod.getStatusLine());
            }
            // read response
            InputStream is = postCertificateRequestMethod.getResponseBodyAsStream();
            Source source = new Source(is);
            checkSLCSResponse(source, "SLCSCertificateResponse");
            parseSLCSCertificateResponse(source);
        } catch (IOException e) {
            final String message = "Failed to request certificate, I/O error: " + e.getMessage();
            LOG.error(message, e);
            throw new SLCSException(message, e);
        } finally {
            postCertificateRequestMethod.releaseConnection();
        }
    }

    private void parseSLCSCertificateResponse(Source source)
            throws SLCSException, IOException {
        Element certificateElement = source.findNextElement(0, "Certificate");
        if (certificateElement == null || certificateElement.isEmpty()) {
            final String message = "Certificate element not found in SLCS response";
            LOG.error(message);
            throw new SLCSException(message);
        }
        String pemCertificate = certificateElement.getContent().toString();
        LOG.info("Certificate element found");
        LOG.debug("Certificate=" + pemCertificate);
        StringReader reader = new StringReader(pemCertificate);
        try {
            certificate_ = Certificate.readPEM(reader);
        } catch (GeneralSecurityException e) {
            final String message = "Failed to reconstitute the certificate: " + e.getMessage();
            LOG.error(message, e);
            throw new SLCSException(message, e);
        }
    }

    /**
     * Creates the certificate keys.
     *
     * @param password The private key password.
     * @throws java.security.GeneralSecurityException
     *          If an error occurs while creating the object.
     */
    public void generateCertificateKeys(char[] password)
            throws GeneralSecurityException {
        LOG.debug("generating keys...");
        certificateKeys_ = new CertificateKeys(getKeySize(), password);
    }

    /**
     * Creates the CeriticateRequest object.
     *
     * @throws java.security.GeneralSecurityException
     *          If an error occurs while creating the object.
     */
    public void generateCertificateRequest() throws GeneralSecurityException {
        LOG.debug("generate CSR: " + certificateSubject_);
        certificateRequest_ = new CertificateRequest(certificateKeys_,
                certificateSubject_, certificateExtensions_);
    }

    private void setContext(DelegationContext context) {
        this.context_ = context;
    }

    private void setWsc(WebServiceClient wsc) {
        this.wsc_ = wsc;
    }

    public void setKeySize(int size) {
        // TODO check valid size
        keySize_ = size;
    }

    public Certificate getCertificate() {
        return certificate_;
    }

    public CertificateKeys getCertificateKeys() {
        return certificateKeys_;
    }

    public int getKeySize() {
        return keySize_;
    }
}