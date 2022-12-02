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
import java.math.BigInteger;
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
import java.util.List;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.util.CertTools;
import org.cesecore.util.ConcurrentCache;
import org.cesecore.util.provider.EkuPKIXCertPathChecker;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpMessageProtectionVerifyer;
import org.ejbca.core.protocol.cmp.CmpPbeVerifyer;
import org.ejbca.core.protocol.cmp.CmpPbmac1Verifyer;
import org.ejbca.core.protocol.cmp.CrmfRequestMessage;
import org.ejbca.core.protocol.cmp.InvalidCmpProtectionException;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;


/**
 * Servlet implementing server side of the Certificate Management Protocols (CMP)
 * 
 */
public class CmpServlet extends HttpServlet {

    public static final int CERTIFICATE_CACHE_VALIDITY = 60000;
    public static final int CACHE_VALIDITY = 5000;
    public static final int CACHE_TIMEOUT = 5000;
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CmpServlet.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    /** Only intended to check if Peer connected instance is authorized to CMP at all. */
    private final AuthenticationToken raCmpAuthCheckToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("cmpProtocolAuthCheck"));
    
    private static final String DEFAULT_CMP_ALIAS = "cmp";
    private AuthenticationToken authenticationToken;

    private ConcurrentCache<String, X509Certificate> extraCertIssuerCache = new ConcurrentCache<>();
    private ConcurrentCache<BigInteger, Boolean> revocationStatusCache = new ConcurrentCache<>(); // 'true' value=>certificate OK => certificate NOT revoked.
    private ConcurrentCache<Integer, X509Certificate> extraCertIssuerCacheByCaId = new ConcurrentCache<>();

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
            if (alias.length() > 32) {
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
                    sendUnprotectedError(response, pkiMessage, msg);
                    return;
                }
                final ASN1ObjectIdentifier protectionAlg = header.getProtectionAlg().getAlgorithm();
                if (config.isInAuthModule(alias, CmpConfiguration.AUTHMODULE_HMAC)
                        && (protectionAlg.equals(CMPObjectIdentifiers.passwordBasedMac) || protectionAlg.equals(PKCSObjectIdentifiers.id_PBMAC1))) {
                    try {
                        validateMAC(pkiMessage, alias, config, messageInformation);
                    } catch (CmpServletValidationError cmpServletValidationError) {
                        sendUnprotectedError(response, pkiMessage, cmpServletValidationError.getMessage());
                        return;
                    }
                } else if (config.isInAuthModule(alias, CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE)) {
                    try {
                        validateMessageSignature(pkiMessage, messageInformation, config, alias);
                    } catch (CmpServletValidationError cmpServletValidationError) {
                        sendUnprotectedError(response, pkiMessage, cmpServletValidationError.getMessage());
                        return;
                    }
                } else {
                    sendUnprotectedError(response, pkiMessage, "Message is not authenticated with a supported authentication method.");
                    return;
                }
                validateCertificateValidity();
                validateCertificateChainValidity();
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

    private void sendUnprotectedError(final HttpServletResponse response, final PKIMessage pkiMessage, final String message)
            throws IOException {
        byte[] errorMessage = CmpMessageHelper.createUnprotectedErrorMessage(pkiMessage.getHeader(),
                FailInfo.BAD_REQUEST, message).getResponseMessage();
        ServletUtils.addCacheHeaders(response);
        RequestHelper.sendBinaryBytes(errorMessage, response, "application/pkixcmp", null);
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
        boolean ok = false;
        final boolean clearCache = StringUtils.equals(request.getParameter("clearcache"), "true");
        if (clearCache) {
            final String ip = request.getRemoteAddr();
            if (StringUtils.equals(ip, "127.0.0.1") || StringUtils.equals(ip, "::1")) { // IPv4 and IPv6
                log.info("Clearing caches in CMP servlet.");
                extraCertIssuerCache.clear();
                extraCertIssuerCacheByCaId.clear();
                revocationStatusCache.clear();
                response.setContentType("text/plain");
                try (ServletOutputStream os = response.getOutputStream()) {
                    os.print("Caches cleared.\n");
                }
                ok = true;
            } else {
                log.info("Clearing of caches is only allowed from localhost, but request was received from: " + ip);
            }
        }
        if (!ok) {
            log.info("Received un-allowed method GET in CMP servlet: query string=" + request.getQueryString());
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
        }
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
    private void validateMessageSignature(final PKIMessage pkimsg, String messageInformation, final CmpConfiguration cmpConfig, final String alias) throws CmpServletValidationError {
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
            X509Certificate extraCertIssuerCertificate;
            if (cmpConfig.getRAMode(alias)) {
                final String issuerCaName = cmpConfig.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE, alias);
                extraCertIssuerCertificate = getIssuerCertificate(issuerCaName, messageInformation);
            } else {
                final String issuerCaSubjectDn = CertTools.getIssuerDN(extraCertificate);
                extraCertIssuerCertificate = getIssuerCertificateByCaId(issuerCaSubjectDn, messageInformation);
            }
            // - verifying the certificate in extraCerts, with the chain configured in the cmp alias
            // - verifying the PKIProtection, using a PKIXPathValidator so both certificate signatures and validity is verified
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
            validateCertificateStatus(extraCertificate, messageInformation);

            try {
                sig.initVerify(extraCertificate.getPublicKey());
                sig.update(CmpMessageHelper.getProtectedBytes(pkimsg));
                if (!sig.verify(pkimsg.getProtection().getBytes())) {
                    // - if verification fails, return a CMP error message
                    String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "Verification of signature failed. " + messageInformation);
                    log.info(msg);
                    throw new CmpServletValidationError(msg);
                }
            } catch (InvalidKeyException | SignatureException e) {
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "Signature defined in CMP message could not be initialized. " + messageInformation, e);
                log.info(msg);
                throw new CmpServletValidationError(msg);
            }
        } else {
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
     * (We currently only support PBE)
     * 
     * CmpProxyServlet.validateCmpMessage()
     * @throws CmpServletValidationError 
     */
    private void validateMAC(PKIMessage pkiMessage, String alias, CmpConfiguration cmpConfiguration, String messageInformation) throws CmpServletValidationError {
        final boolean raMode = cmpConfiguration.getRAMode(alias);
        String passwd = null;
        String requestAuthParam = null;
        CmpMessageProtectionVerifyer verifier;
        try {
            final ASN1ObjectIdentifier protectionAlgorithm = pkiMessage.getHeader().getProtectionAlg().getAlgorithm();
            if (protectionAlgorithm.equals(CMPObjectIdentifiers.passwordBasedMac)) {
                verifier = new CmpPbeVerifyer(pkiMessage);
            } else if (protectionAlgorithm.equals(PKCSObjectIdentifiers.id_PBMAC1)) {
                verifier = new CmpPbmac1Verifyer(pkiMessage);
            } else {
                // Should not happen since the message should have been checked for a valid protection header already
                throw new CmpServletValidationError("PKIMessage is not protected by passwordBasedMac or PBMAC1");
            }
        } catch (InvalidCmpProtectionException e) {
            //Safe to ignore, because we've already checked this case.
            throw new IllegalStateException(e);
        }
        if (raMode) {
            // Is the secret specified in the CMP alias? (Formerly specified in cmpProxy.properties)
            passwd = cmpConfiguration.getAuthenticationParameter(CmpConfiguration.AUTHMODULE_HMAC, alias);
            if (StringUtils.isEmpty(passwd) || "-".equals(passwd)) {
                final boolean isRaCaNameKeyId = StringUtils.equals(cmpConfiguration.getRACAName(alias), CmpConfiguration.PROFILE_USE_KEYID);
                final boolean isRaEEPKeyId = StringUtils.equals(cmpConfiguration.getRAEEProfile(alias), CmpConfiguration.PROFILE_USE_KEYID);
                final boolean isRaCPKeyId = StringUtils.equals(cmpConfiguration.getRACertProfile(alias), CmpConfiguration.PROFILE_USE_KEYID);
                final String caName;
                if (isRaCaNameKeyId && (isRaEEPKeyId || isRaCPKeyId)) {
                    // If true, then senderKeyId has caname... get CA CMP RA Shared Secret
                    caName = CmpMessageHelper.getStringFromOctets(pkiMessage.getHeader().getSenderKID());
                    passwd = getCaSecretFromCaUsingCaName(caName);
                    // If not from sender KID, try RA CA Name configuration in alias to get CA and secret... 
                } else if (!StringUtils.equals(cmpConfiguration.getRACAName(alias), CmpConfiguration.PROFILE_DEFAULT)) {
                    caName = cmpConfiguration.getRACAName(alias);
                    passwd = getCaSecretFromCaUsingCaName(caName);
                } else {
                    // Finally, try to get CA from end entity profile and get secret
                    final String profile = cmpConfiguration.getRAEEProfile(alias);
                    final IdNameHashMap<EndEntityProfile> eeplist = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(authenticationToken, AccessRulesConstants.CREATE_END_ENTITY);
                    final KeyToValueHolder<EndEntityProfile> holder = eeplist.get(Integer.valueOf(profile));
                    final EndEntityProfile eep = holder.getValue();
                    if (eep != null) {
                        int caId = eep.getDefaultCA();
                        passwd = getCaSecretFromCaUsingCaId(caId);
                    }
                }
            } 
        } else {
            final String errmsg = intres.getLocalizedMessage("cmp.errorauthmessage", "Extended validation using Pbe HMAC validation not supported for Client Mode");
            throw new CmpServletValidationError(errmsg);
        }
        if (passwd == null) {
            final String logmsg = "Pbe HMAC field was encountered, but no configured authentication secret was found.";
            log.info(logmsg);
            // Use a shorter error messages that is returned to client, because we don't want to leak any information about configured secrets
            final String errmsg = intres.getLocalizedMessage("cmp.errorauthmessage", "Pbe HMAC field was encountered, but HMAC did not verify",
                    messageInformation);
            throw new CmpServletValidationError(errmsg);
        }
        try {
            if (verifier.verify(passwd) == false) {
                String msg = intres.getLocalizedMessage("cmp.errorauthmessage", "Failed to verify message using both Global Shared Secret and CMP RA Authentication Secret");
                log.info(msg);
                throw new CmpServletValidationError(msg);
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | CMPException e) {
            String msg = intres.getLocalizedMessage("cmp.errorauthmessage", messageInformation, e.getMessage());
            log.info(msg);
            throw new CmpServletValidationError(msg);
        }
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
     * The revocation status of the signature certificate must be checked
     *
     */
    private void validateCertificateStatus(final X509Certificate cert, final String messageInformation) throws CmpServletValidationError {
        BigInteger certSerialnumber = CertTools.getSerialNumber(cert);
        ConcurrentCache<BigInteger, Boolean>.Entry invokerEntry = revocationStatusCache.openCacheEntry(certSerialnumber, CACHE_TIMEOUT); // should never time out, unless a very small (< 100ms) timeout is used
        if (invokerEntry == null) {
            String msg = "Timed out waiting other thread to fetch revocation status from cache.";
            log.info(msg + " " + messageInformation);
            throw new CmpServletValidationError(msg);

        }
        try {
            String msg = intres.getLocalizedMessage("cmp.errorauthmessage",
                    "Signing certificate in CMP message was revoked");
            if (invokerEntry.isInCache()) { // if the cache entry has expired, this method will return false
                if (log.isDebugEnabled()) {
                    log.debug("Using revocation status from the cache");
                }
                if (!invokerEntry.getValue()) { // 'true' value => certificate is OK => NOT revoked
                    log.info(msg + " " + messageInformation);
                    throw new CmpServletValidationError(msg);
                }
            } else {
                CertificateStatus certificateStatus = null;
                try {
                    certificateStatus = raMasterApiProxyBean.getCertificateStatus(raCmpAuthCheckToken, cert.getIssuerDN().getName(), certSerialnumber);
                } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                    log.info(e.getLocalizedMessage());
                    throw new CmpServletValidationError(msg);
                }
                boolean isRevoked = certificateStatus.equals(CertificateStatus.REVOKED);
                invokerEntry.putValue(!isRevoked); // 'True' => certificate NOT revoked
                invokerEntry.setCacheValidity(CACHE_VALIDITY);
                if (isRevoked) {
                    log.info(msg);
                    throw new CmpServletValidationError(msg);
                }
            }
        } finally {
            invokerEntry.close();
        }
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

    private X509Certificate getIssuerCertificate(final String caName, String messageInformation) throws CmpServletValidationError {

        ConcurrentCache<String, X509Certificate>.Entry cacertEntry = extraCertIssuerCache.openCacheEntry(caName, CACHE_TIMEOUT); // should never time out, unless a very small (< 100ms) timeout is used
        if (cacertEntry == null) {
            String msg = "Timed out waiting other thread to fetch certificate issuer's certificate from cache";
            log.info(msg);
        }

        try {
            // If the CA cert is in the cache, use that CA cert
            if ((cacertEntry != null) && (cacertEntry.isInCache())) {
                X509Certificate cacert = cacertEntry.getValue();
                log.info("Found CA certificate with CaName " + caName + " in the cache");
                return cacert;
            }
            if (log.isDebugEnabled()) {
                log.debug("Did not find CA certificate with CaName " + caName + " in the cache. Asking from RaMasterApi");
            }

            try {
                Collection<CertificateWrapper> lastCaChain = raMasterApiProxyBean.getLastCaChain(authenticationToken, caName);
                X509Certificate cacert = (X509Certificate) lastCaChain.iterator().next().getCertificate();
                if (cacertEntry != null) { // put the CA cert in the cache
                    cacertEntry.putValue(cacert);
                    cacertEntry.setCacheValidity(CERTIFICATE_CACHE_VALIDITY);
                    return cacert;
                }
            } catch (CADoesntExistsException | AuthorizationDeniedException e) {
                String msg = "Issuer ca form CMP alias does not exist or is not accessible. CA name: " + caName;
                if (log.isDebugEnabled()) {
                    log.debug(msg + " - " + e.getLocalizedMessage());
                }
            }

        } finally {
            if (cacertEntry != null) {
                cacertEntry.close();
            }
        }

        String msg = intres.getLocalizedMessage("Failed to find Issuer CA " + caName);
        log.info(msg + " " + messageInformation);
        throw new CmpServletValidationError(msg);
    }

    private X509Certificate getIssuerCertificateByCaId(final String caSubjectDn, String messageInformation) throws CmpServletValidationError {
        final int caId = caSubjectDn.hashCode();
        ConcurrentCache<Integer, X509Certificate>.Entry cacertEntry = extraCertIssuerCacheByCaId.openCacheEntry(caId, CACHE_TIMEOUT); // should never time out, unless a very small (< 100ms) timeout is used
        if (cacertEntry == null) {
            String msg = "Timed out waiting other thread to fetch certificate issuer's certificate from cache";
            log.info(msg);
        }

        try {
            // If the CA cert is in the cache, use that CA cert
            if ((cacertEntry != null) && (cacertEntry.isInCache())) {
                X509Certificate cacert = cacertEntry.getValue();
                log.info("Found CA certificate with subject dn " + caSubjectDn + " in the cache");
                return cacert;
            }
            if (log.isDebugEnabled()) {
                log.debug("Did not find CA certificate with subject dn " + caSubjectDn + " in the cache. Asking from RaMasterApi");
            }

            try {
                Collection<CertificateWrapper> lastCaChain = raMasterApiProxyBean.getCertificateChain(authenticationToken, caId);
                X509Certificate cacert = (X509Certificate) lastCaChain.iterator().next().getCertificate();
                if (cacertEntry != null) { // put the CA cert in the cache
                    cacertEntry.putValue(cacert);
                    cacertEntry.setCacheValidity(CERTIFICATE_CACHE_VALIDITY);
                    return cacert;
                }
            } catch (CADoesntExistsException | AuthorizationDeniedException | EJBException e) {
                String msg = "Issuer ca form CMP alias does not exist or is not accessible. CA subject Dn: " + caSubjectDn;
                if (log.isDebugEnabled()) {
                    log.debug(msg + " - " + e.getLocalizedMessage());
                }
                throw new CmpServletValidationError(msg);
            }

        } finally {
            if (cacertEntry != null) {
                cacertEntry.close();
            }
        }
        String msg = intres.getLocalizedMessage("Failed to find Issuer CA " + caSubjectDn);
        log.info(msg + " " + messageInformation);
        throw new CmpServletValidationError(msg);
    }

    private String getCaSecretFromCaUsingCaName(final String caName) {
        final List<CAInfo> cainfolist = raMasterApiProxyBean.getAuthorizedCas(authenticationToken);
        for (final CAInfo cainfo : cainfolist) {
            if (cainfo.getName().equals(caName)) {
                final X509CAInfo x509cainfo = (X509CAInfo)cainfo;
                return x509cainfo.getCmpRaAuthSecret();
            }
        }
        return null;
     }
    
     private String getCaSecretFromCaUsingCaId(final int caid) {
        final List<CAInfo> cainfolist = raMasterApiProxyBean.getAuthorizedCas(authenticationToken);
        for (final CAInfo cainfo : cainfolist ) {
            if (cainfo.getCAId() == caid) {
                final X509CAInfo x509cainfo = (X509CAInfo)cainfo;
                return x509cainfo.getCmpRaAuthSecret();
            }
        }
        return null;
     }

}
