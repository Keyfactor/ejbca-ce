/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import javax.ejb.EJB;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.provider.EkuPKIXCertPathChecker;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet implementing server side of the Certificate Management Protocols (CMP)
 * 
 */
public class CmpServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CmpServlet.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    /** Only intended to check if Peer connected instance is authorized to CMP at all. */
    private final AuthenticationToken raCmpAuthCheckToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("cmpProtocolAuthCheck"));
    
    private static final String DEFAULT_CMP_ALIAS = "cmp";
    private AuthenticationToken authenticationToken;
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    /**
     * Handles HTTP post
     * 
     * @param request java standard arg
     * @param response java standard arg
     * 
     * @throws IOException input/output error
     */
    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (request.getContentLengthLong() < 0 && request.getHeader("Transfer-Encoding")==null) {
            log.error("Missing Content-Length header and Transfer-Encoding header");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing Content-Length header and Transfer-Encoding header.");
            return;
        }
        if (log.isTraceEnabled()) {
            log.trace(">doPost()");
        }
        boolean isProtocolAuthorized = raMasterApiProxyBean.isAuthorizedNoLogging(raCmpAuthCheckToken, AccessRulesConstants.REGULAR_PEERPROTOCOL_CMP);
        try {
            if (!isProtocolAuthorized) {
                log.info("CMP Protocol not authorized for this Peer");
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "CMP Protocol not authorized for this Peer");
                return;
            }
            final String alias = getAlias(request.getPathInfo());
            if(alias.length() > 32) {
                log.info("Unaccepted alias more than 32 characters.");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unaccepted alias more than 32 characters.");
                return;
            }
            final ServletInputStream sin = request.getInputStream();
            // This small code snippet is inspired/copied by apache IO utils to Tomas Gustavsson...
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final byte[] buf = new byte[1024];
            int n = 0;
            int bytesRead = 0;
            while (-1 != (n = sin.read(buf))) {
                bytesRead += n;
                if (bytesRead > LimitLengthASN1Reader.MAX_REQUEST_SIZE) {
                    throw new IllegalArgumentException("Request is larger than "+LimitLengthASN1Reader.MAX_REQUEST_SIZE+" bytes.");
                }
                output.write(buf, 0, n);
            }
            authenticationToken = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal("CmpServlet", request.getRemoteAddr()));
            CmpConfiguration config = raMasterApiProxyBean.getGlobalConfiguration(CmpConfiguration.class);
            byte[] pkiMessageBytes = output.toByteArray();
            if (config.getUseExtendedValidation(alias)) {
                // Perform extended validation. To be implemented in ECA-11035
                PKIMessage pkiMessage;
                try {
                    pkiMessage = getPkiMessage(pkiMessageBytes);
                } catch (CmpServletValidationError cmpServletValidationError) {
                    byte[] errorMessage = CmpMessageHelper.createUnprotectedErrorMessage(cmpServletValidationError.getMessage());
                    ServletUtils.addCacheHeaders(response);
                    RequestHelper.sendBinaryBytes(errorMessage, response, "application/pkixcmp", null);
                    return;
                }
                final PKIHeader header = pkiMessage.getHeader();
                String messageInformation = "CMP message: pvno = " + header.getPvno() +
                        ", sender = " + header.getSender().toString() +
                        ", recipient = " + header.getRecipient().toString() +
                        ", transactionID = " + header.getTransactionID();
                log.info("Validating CMP message: " + messageInformation);
                if (pkiMessage.getProtection() == null) {
                    //No protection was found
                    String msg = intres.getLocalizedMessage("cmp.errorauthmessage",
                            "Signature/HMAC verification was required by CMP RA, but not found in message");
                    log.info(msg + " " + messageInformation);
                    byte[] errorMessage = CmpMessageHelper.createUnprotectedErrorMessage(pkiMessage.getHeader(), FailInfo.BAD_REQUEST, msg).getResponseMessage();
                    ServletUtils.addCacheHeaders(response);
                    RequestHelper.sendBinaryBytes(errorMessage, response, "application/pkixcmp", null);
                    return;
                }
                if (config.isInAuthModule(alias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
                    try {
                        final String issuerCaName = config.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, alias);
                        validateMessageSignature(pkiMessage, messageInformation, issuerCaName);
                    } catch (CmpServletValidationError cmpServletValidationError) {
                        byte[] errorMessage = CmpMessageHelper.createUnprotectedErrorMessage(pkiMessage.getHeader(),
                                FailInfo.BAD_REQUEST, cmpServletValidationError.getMessage()).getResponseMessage();
                        ServletUtils.addCacheHeaders(response);
                        RequestHelper.sendBinaryBytes(errorMessage, response, "application/pkixcmp", null);
                        return;
                    }
                }

                validateMAC();
                validateCertificateChain();
                validateCertificateValidity();
                validateCertificateChainValidity();
                validateCertificateStatus();
                validateCertificateChainStatus();
            }
            
            service(pkiMessageBytes, request.getRemoteAddr(), response, alias);
        } catch (IOException | RuntimeException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            log.info(intres.getLocalizedMessage("cmp.errornoasn1"), e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<doPost()");
        }
    }

    /**
     * Handles HTTP get
     * 
     * @param request java standard arg
     * @param response java standard arg
     * 
     * @throws IOException input/output error
     */
    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (log.isTraceEnabled()) {
            log.trace(">doGet()");
        }
        log.info("Received un-allowed method GET in CMP servlet: query string=" + request.getQueryString());
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
        if (log.isTraceEnabled()) {
            log.trace("<doGet()");
        }
    }

    private void service(final byte[] pkiMessageBytes, final String remoteAddr, final HttpServletResponse response, String alias) throws IOException {
        try {
            log.info(intres.getLocalizedMessage("cmp.receivedmsg", remoteAddr, alias));
            final long startTime = System.currentTimeMillis();
            byte[] result;
            try {
                result = raMasterApiProxyBean.cmpDispatch(authenticationToken, pkiMessageBytes, alias);
            } catch (NoSuchAliasException e) {
                // The CMP alias does not exist
                response.sendError(HttpServletResponse.SC_NOT_FOUND, e.getMessage());
                log.info(e.getMessage());
                return;
            }
            if (result == null) {
                // If resp is null, it means that the dispatcher failed to process the message.
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, intres.getLocalizedMessage("cmp.errornullresp"));
                return;
            }
            // Add no-cache headers as defined in 
            // http://tools.ietf.org/html/draft-ietf-pkix-cmp-transport-protocols-14
            ServletUtils.addCacheHeaders(response);
            // Send back CMP response
            RequestHelper.sendBinaryBytes(result, response, "application/pkixcmp", null);
            final long endTime = System.currentTimeMillis();
            log.info(intres.getLocalizedMessage("cmp.sentresponsemsg", remoteAddr, endTime - startTime));
        } catch (IOException | RuntimeException e) {
            log.error("Error in CmpServlet:", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
    
    private String getAlias(final String pathInfo) {
        // PathInfo contains the alias used for CMP configuration. 
        // The CMP URL for custom configuration looks like: http://HOST:PORT/ejbca/publicweb/cmp/*
        // pathInfo contains what * is and should have the form "/<SOME IDENTIFYING TEXT>". We extract the "SOME IDENTIFYING 
        // TEXT" and that will be the CMP configuration alias.
        final String alias;
        if (pathInfo!=null && pathInfo.length()>1) {
            alias = pathInfo.substring(1);
            if (log.isDebugEnabled()) {
                log.debug("Using CMP configuration alias: " + alias);
            }
        } else {
            alias = DEFAULT_CMP_ALIAS;
            if (log.isDebugEnabled()) {
                log.debug("No CMP alias specified in the URL. Using the default alias: " + DEFAULT_CMP_ALIAS);
            }
        }
        return alias;
    }

    /**
     * The signature contained in the PKIProtection (s. [rfc4210]) data structure must be cryptographically verified on the CMP proxy if “Signature”
     * is used as protection. The signature certificate/key must be contained in the extraCerts structure.
     *
     * CmpProxyServlet.assertMessageSignature()
     *
     */
    private void validateMessageSignature(final PKIMessage pkimsg, String messageInformation, final String issuerCaName) throws CmpServletValidationError {
        final PKIHeader header = pkimsg.getHeader();
        AlgorithmIdentifier protectionAlgorithm = header.getProtectionAlg();
        Signature sig;
        try {
            sig = Signature.getInstance(protectionAlgorithm.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            sig = null;
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("No BouncyCastle provider was found.", e);
        }
        if (sig != null) {
            // A signature was specified, and the configuration allows signatures.
            // - check if PKIProtection is digital signature and if there is a signer certificate in extraCerts
            CMPCertificate[] extraCerts = pkimsg.getExtraCerts();
            if (extraCerts == null || extraCerts.length == 0 || extraCerts[0] == null) {
                //No signing certificate was provided
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "ExtraCerts field was blank, could not verify signature.");
                log.info(msg + " " + messageInformation);
                throw new CmpServletValidationError(msg);
            }
            X509Certificate extraCertificate;
            try {
                extraCertificate = CertTools.getCertfromByteArray(extraCerts[0].getEncoded(), X509Certificate.class);
            } catch (CertificateParsingException | IOException e) {
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "ExtraCerts field was not blank, but could not be parsed into a certificate.");
                log.info(msg + " " + messageInformation);
                throw new CmpServletValidationError(msg);
            }
            // - verifying the certificate in extraCerts, with the chain configured in the cmp alias
            // - verifying the PKIProtection, using a PKIXPathValidator so both certificate signatures and validity is verified
            X509Certificate extraCertIssuerCertificate = getIssuerCertificate(issuerCaName);
            if (extraCertIssuerCertificate == null) {
                String msg = intres.getLocalizedMessage("Failed to find Issuer CA " + issuerCaName);
                log.info(msg + " " + messageInformation);
                throw new CmpServletValidationError(msg);
            }
            Collection<X509Certificate> caCertificateChain = Collections.singleton(extraCertIssuerCertificate);

            try {
                CertTools.verify(extraCertificate, caCertificateChain, null, new EkuPKIXCertPathChecker());
            } catch (CertPathValidatorException e) {
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", e.getLocalizedMessage());
                log.info(msg + " " + messageInformation);
                throw new CmpServletValidationError(msg);
            }

            // Because we should use values from the cache if available, and because we should update the cache if there are new information, whether
            // the extraCertificate was revoked or not, this PKIXCertPathChecker was not added to the list of checkers to be verified in
            // CertTools.verify() line above
            // TODO checkRevocationStatus ECA-11035

            try {
                sig.initVerify(extraCertificate.getPublicKey());
                sig.update(CmpMessageHelper.getProtectedBytes(pkimsg));
                if (!sig.verify(pkimsg.getProtection().getBytes())) {
                    // - if verification fails, return a CMP error message
                    String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "Verification of signature failed. " + messageInformation);
                    log.info(msg);
                    throw new CmpServletValidationError(msg);
                }
                // - if verification is successful, put message in External RA database (i.e. continue from this point on)
            } catch (InvalidKeyException | SignatureException e) {
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "Signature defined in CMP message could not be initialized. " + messageInformation, e);
                log.info(msg);
                throw new CmpServletValidationError(msg);
            }
        } else {
            // We've ended up here if HMAC or Signature were specified, but neither fulfilled.
            String msg = intres.getLocalizedMessage("cmp.errorauthmessage",
                    "CMP Message Protection verification failed. Server is configured for "
                            +  "Signature validation. " + "Algorithm with ID ("
                            + header.getProtectionAlg().getAlgorithm().getId() + ") was found instead");
            log.info(msg);
            throw new CmpServletValidationError(msg);
        }
    }

    /**
     * The MAC contained in the PKIProtection data structure must be cryptographically verified on the CMP proxy if “DH Key Pairs” is used as protection.
     * The DH cert/key information must be stored in the extraCerts structure.
     *
     * CmpProxyServlet.validateCmpMessage()
     */
    private boolean validateMAC(){
        return true;
    }

    /**
     * The certificate chain of the signature certificate must be validated
     *
     * CmpProxyServlet.validateCmpMessage()
     */
    private boolean validateCertificateChain(){
        return true;
    }

    /**
     * The validity interval of the certificate must be checked
     *
     * CmpProxyServlet.validateCmpMessage()
     */
    private boolean validateCertificateValidity(){
        return true;
    }

    /**
     * The validity interval of all chain certificate must be checked
     *
     *
     */
    private boolean validateCertificateChainValidity(){
        return true;
    }

    /**
     * The revocation status of the signature certificate must be checked against a current CRL of the issuing CA and/or via OCSP
     *
     * CmpProxyServlet.checkRevocationStatus. We should be able to do this internally moving forward.
     */
    private boolean validateCertificateStatus(){
        return true;
    }

    /**
     * The revocation status of all chain certificates must be checked against a current CRL of the respective issuing CA
     *
     * CmpProxyServlet.checkRevocationStatus
     */
    private boolean validateCertificateChainStatus(){
        return true;
    }

    private PKIMessage getPkiMessage(byte[] pkiMessageBytes) throws CmpServletValidationError {

        final PKIMessage pkimsg;
        try {
            pkimsg = PKIMessage.getInstance(pkiMessageBytes);
        } catch (IllegalArgumentException e) {
            //BouncyCastle will throw an IllegalArgumentException if the ASN.1 in the message doesn't parse.
            String msg = intres.getLocalizedMessage("cmp.errornotcmpmessage");
            log.info(msg);
            throw new CmpServletValidationError(msg);
        }
        return pkimsg;
    }

    private X509Certificate getIssuerCertificate(String caName) {
        try {
            Collection<CertificateWrapper> lastCaChain = raMasterApiProxyBean.getLastCaChain(authenticationToken, caName);
            return (X509Certificate) lastCaChain.iterator().next().getCertificate();
        } catch (CADoesntExistsException | AuthorizationDeniedException e) {
            String msg = "Issuer ca form CMP alias does not exist or is not accessible. CA name: " + caName;
            if (log.isDebugEnabled()) {
                log.debug(msg + " - " + e.getLocalizedMessage());
            }
        }
        return null;
    }

}
