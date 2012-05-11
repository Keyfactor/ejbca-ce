/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.ejb.EJB;
import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.jcajce.JcaRespID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.DirectoryCache;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.cache.OcspExtensionsCache;
import org.cesecore.certificates.ocsp.cache.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.certificates.ocsp.exception.CryptoProviderException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.exception.NotSupportedException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.log.ProbableErrorHandler;

/**
 * Common abstract class for OCSP response generator session beans.
 * 
 * @version $Id$
 * 
 */

enum CanLogCache {
    INSTANCE;

    private CanLogCache() {
        this.canLog = true;
    }

    private boolean canLog;

    public boolean canLog() {
        return canLog;
    }

    public void setCanLog(boolean canLog) {
        this.canLog = canLog;
    }
}

public abstract class OcspResponseSessionBean implements OcspResponseGeneratorSession {

    private static final Logger log = Logger.getLogger(OcspResponseSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();

    /** Max size of a request is 100000 bytes */
    private static final int MAX_REQUEST_SIZE = 100000;

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    private JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
    
    /**
     * Use this method to perform any ops that can't be done in @PostConstruct, if necessary.
     */
    protected abstract void initiateIfNecessary();

    /**
     * 
     * @return a reference to the extending bean's token and chain cache. Allows different children to use separate caches.
     */
    protected abstract TokenAndChainCache getTokenAndChainCache();

    @Override
    public OcspResponseInformation getOcspResponse(final byte[] request,
            final X509Certificate[] requestCertificates, String remoteAddress, String remoteHost, StringBuffer requestUrl,
            final AuditLogger auditLogger, final TransactionLogger transactionLogger) throws MalformedRequestException, IOException, OCSPException {
        initiateIfNecessary();

        //Check parameters
        if (auditLogger == null) {
            throw new InvalidParameterException("Illegal to pass a null audit logger to OcspResponseSession.getOcspResponse");
        }
        //Check parameters
        if (transactionLogger == null) {
            throw new InvalidParameterException("Illegal to pass a null transaction logger to OcspResponseSession.getOcspResponse");
        }

        // Validate byte array.
        if (request.length > MAX_REQUEST_SIZE) {
            final String msg = intres.getLocalizedMessage("request.toolarge", MAX_REQUEST_SIZE, request.length);
            throw new MalformedRequestException(msg);
        }

        byte[] respBytes = null;

        final Date startTime = new Date();

        OCSPResp ocspResponse = null;

        // Start logging process time after we have received the request
        transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        auditLogger.paramPut(AuditLogger.OCSPREQUEST, new String(Hex.encode(request)));

        OCSPReq req;

        long maxAge = OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        OCSPRespBuilder responseGenerator = new OCSPRespBuilder();
        try {
            req = translateRequestFromByteArray(request, remoteAddress, transactionLogger);

            // Get the certificate status requests that are inside this OCSP req
            Req[] ocspRequests = req.getRequestList();

            if (ocspRequests.length <= 0) {
                String infoMsg = intres.getLocalizedMessage("ocsp.errornoreqentities");
                log.info(infoMsg);
                throw new MalformedRequestException(infoMsg);
            }
            final int maxRequests = 100;
            if (ocspRequests.length > maxRequests) {
                String infoMsg = intres.getLocalizedMessage("ocsp.errortoomanyreqentities", maxRequests);
                log.info(infoMsg);
                throw new MalformedRequestException(infoMsg);
            }

            if (log.isDebugEnabled()) {
                log.debug("The OCSP request contains " + ocspRequests.length + " simpleRequests.");
            }

            transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
            auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);

            CryptoTokenAndChain signerTokenAndChain = null;

            long nextUpdate = OcspConfiguration.getUntilNextUpdate(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);

            // Add standard response extensions
            Hashtable<ASN1ObjectIdentifier, Extension> responseExtensions = getStandardResponseExtensions(req);


            // Look for extension OIDs
            final Collection<String> extensionOids = OcspConfiguration.getExtensionOids();

            // Look over the status requests
            List<OCSPResponseItem> responseList = new ArrayList<OCSPResponseItem>();
            for (Req ocspRequest : ocspRequests) {
                CertificateID certId = ocspRequest.getCertID();

                transactionLogger.paramPut(TransactionLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
                // TODO:find text version of this or find out if it should be something else
                transactionLogger.paramPut(TransactionLogger.DIGEST_ALGOR, certId.getHashAlgOID().getEncoded());
                transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
                transactionLogger.paramPut(TransactionLogger.ISSUER_KEY, certId.getIssuerKeyHash());
                auditLogger.paramPut(AuditLogger.ISSUER_KEY, certId.getIssuerKeyHash());
                auditLogger.paramPut(AuditLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
                auditLogger.paramPut(AuditLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());

                byte[] hashbytes = certId.getIssuerNameHash();
                String hash = null;
                if (hashbytes != null) {
                    hash = new String(Hex.encode(hashbytes));
                }
                String infoMsg = intres.getLocalizedMessage("ocsp.inforeceivedrequest", certId.getSerialNumber().toString(16), hash, remoteAddress);
                log.info(infoMsg);

                // Locate the CA which gave out the certificate
                signerTokenAndChain = getTokenAndChainCache().get(certId);
                /*
                 * if the certId was issued by an unknown CA 
                 * 
                 * The algorithm here: 
                 * We will sign the response with the CA that issued the last certificate(certId) in the request. If the issuing CA is not available on 
                 * this server, we sign the response with the default responderId (from params in web.xml). We have to look up the ca-certificate for 
                 * each certId in the request though, as we will check for revocation on the ca-cert as well when checking for revocation on the certId.
                 */

                if (signerTokenAndChain != null) {
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN, signerTokenAndChain.getCaCertificate().getSubjectDN().getName());
                } else {
                    // We could not find certificate for this request so get certificate for default responder
                    signerTokenAndChain = getTokenAndChainCache().getForDefaultResponder();
                    if (signerTokenAndChain != null) {
                        String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacertusedefault",
                                new String(Hex.encode(certId.getIssuerNameHash())));
                        log.info(errMsg);
                        // If we can not find the CA, answer UnknowStatus
                        responseList.add(new OCSPResponseItem(certId, new UnknownStatus(), nextUpdate));
                        transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_UNKNOWN);
                        transactionLogger.writeln();
                        continue;
                    } else {
                        String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacert", new String(Hex.encode(certId.getIssuerNameHash())),
                                OcspConfiguration.getDefaultResponderId());
                        log.error(errMsg);
                        continue;
                    }
                }

                /*
                 * Implement logic according to chapter 2.7 in RFC2560
                 * 
                 * 2.7 CA Key Compromise If an OCSP responder knows that a particular CA's private key has been compromised, it MAY return the revoked
                 * state for all certificates issued by that CA.
                 */
                final org.bouncycastle.cert.ocsp.CertificateStatus certStatus;
                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_GOOD); // it seems to be correct

                // Check if the cacert (or the default responderid) is revoked
                X509Certificate caCertificate = signerTokenAndChain.getCaCertificate();
                final CertificateStatus signerIssuerCertStatus = certificateStoreSession.getStatus(CertTools.getSubjectDN(caCertificate),
                        CertTools.getSerialNumber(caCertificate));

                String subjectDn = caCertificate.getSubjectDN().getName();
                if (!signerIssuerCertStatus.equals(CertificateStatus.REVOKED)) {

                    // Check if cert is revoked
                    final CertificateStatus status = certificateStoreSession.getStatus(subjectDn, certId.getSerialNumber());

                    /* If we have different maxAge and untilNextUpdate for different certificate profiles, we have to fetch these
                     values now that we have fetched the certificate status, that includes certificate profile.*/
                    nextUpdate = OcspConfiguration.getUntilNextUpdate(status.certificateProfileId);
                    maxAge = OcspConfiguration.getMaxAge(status.certificateProfileId);
                    if (log.isDebugEnabled()) {
                        log.debug("Set nextUpdate=" + nextUpdate + ", and maxAge=" + maxAge + " for certificateProfileId="
                                + status.certificateProfileId);
                    }

                    final String sStatus;
                    if (status.equals(CertificateStatus.NOT_AVAILABLE)) {
                        // No revocation info available for this cert, handle it
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to find revocation information for certificate with serial '" + certId.getSerialNumber().toString(16)
                                    + "'" + " from issuer '" + subjectDn + "'");
                        }
                        /* 
                         * If we do not treat non existing certificates as good
                         * OR
                         * we don't actually handle requests for the CA issuing the certificate asked about
                         * then we return unknown 
                         * */
                        if ((!OcspConfigurationCache.INSTANCE.isNonExistingGood(requestUrl)) || (getTokenAndChainCache().get(certId) == null)) {
                            sStatus = "unknown";
                            certStatus = new UnknownStatus();

                        } else {
                            sStatus = "good";
                            certStatus = null; // null means "good" in OCSP

                        }
                    } else if (status.equals(CertificateStatus.REVOKED)) {
                        // Revocation info available for this cert, handle it
                        sStatus = "revoked";
                        certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(status.revocationDate),
                                CRLReason.lookup(status.revocationReason)));
                    } else {
                        sStatus = "good";
                        certStatus = null;

                    }
                    infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", sStatus, certId.getSerialNumber().toString(16), subjectDn);
                    log.info(infoMsg);
                    responseList.add(new OCSPResponseItem(certId, certStatus, nextUpdate));

                } else {
                    certStatus = new RevokedStatus(new RevokedInfo(new DERGeneralizedTime(signerIssuerCertStatus.revocationDate),
                            CRLReason.lookup(signerIssuerCertStatus.revocationReason)));
                    infoMsg = intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", "revoked", certId.getSerialNumber().toString(16), subjectDn);
                    log.info(infoMsg);
                    responseList.add(new OCSPResponseItem(certId, certStatus, nextUpdate));

                }
                for (String oidstr : extensionOids) {
                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidstr);
                 
                    if (req.hasExtensions()) {
                        Extension ext = req.getExtension(oid);
                        if (null != ext) {
                            // We found an extension, call the extension class
                            if (log.isDebugEnabled()) {
                                log.debug("Found OCSP extension oid: " + oidstr);
                            }
                            OCSPExtension extObj = OcspExtensionsCache.INSTANCE.getExtensions().get(oidstr);
                            if (extObj != null) {
                                // Find the certificate from the certId
                                X509Certificate cert = null;
                                cert = (X509Certificate) certificateStoreSession.findCertificateByIssuerAndSerno(subjectDn, certId.getSerialNumber());
                                if (cert != null) {
                                    // Call the OCSP extension
                                    Map<ASN1ObjectIdentifier, Extension> retext = extObj.process(requestCertificates, remoteAddress, remoteHost,
                                            cert, certStatus);
                                    if (retext != null) {
                                        // Add the returned X509Extensions to the responseExtension we will add to the basic OCSP response
                                        responseExtensions.putAll(retext);
                                    } else {
                                        String errMsg = intres.getLocalizedMessage("ocsp.errorprocessextension", extObj.getClass().getName(),
                                                Integer.valueOf(extObj.getLastErrorCode()));
                                        log.error(errMsg);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (signerTokenAndChain != null) {
                // Add responseExtensions
                Extensions exts = new Extensions(responseExtensions.values().toArray(new Extension[0]));
                //X509Extensions exts = new X509Extensions(responseExtensions);
                // generate the signed response object

                final X509Certificate[] signerChain = signerTokenAndChain.getChain();
                final PrivateKey privateKey = signerTokenAndChain.getPrivateKey();
                final String privateKeyProvider = signerTokenAndChain.getSignProviderName();
                BasicOCSPResp basicresp = signOcspResponse(req, responseList, exts, signerChain, privateKey, privateKeyProvider);
                ocspResponse = responseGenerator.build(OCSPRespBuilder.SUCCESSFUL, basicresp);
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
            } else {
                // Only unknown CAs in requests and no default responder's cert
                String errMsg = intres.getLocalizedMessage("ocsp.errornocacreateresp");
                log.error(errMsg);
                throw new OcspFailureException(errMsg);
            }
        } catch (SignRequestException e) {
            transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.SIG_REQUIRED, null);
            transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
            transactionLogger.writeln();
            auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
        } catch (SignRequestSignatureException e) {
            transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
            transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
            transactionLogger.writeln();
            auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
        } catch (NoSuchAlgorithmException e) {
            ocspResponse = processDefaultError(responseGenerator, transactionLogger, auditLogger, e);
        } catch (CertificateException e) {
            ocspResponse = processDefaultError(responseGenerator, transactionLogger, auditLogger, e);
        } catch (CryptoTokenOfflineException e) {
            ocspResponse = processDefaultError(responseGenerator, transactionLogger, auditLogger, e);
        }

        try {
            respBytes = ocspResponse.getEncoded();
            auditLogger.paramPut(AuditLogger.OCSPRESPONSE, new String(Hex.encode(respBytes)));
            auditLogger.writeln();
            auditLogger.flush();
            transactionLogger.flush();
            if (OcspConfiguration.getLogSafer()) {
                // See if the Errorhandler has found any problems
                if (hasErrorHandlerFailedSince(startTime)) {
                    log.info("ProbableErrorhandler reported error, cannot answer request");
                    // RFC 2560: responseBytes are not set on error.
                    ocspResponse = responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);

                }
                // See if the Appender has reported any problems
                if (!CanLogCache.INSTANCE.canLog()) {
                    log.info("SaferDailyRollingFileAppender reported error, cannot answer request");
                    // RFC 2560: responseBytes are not set on error.
                    ocspResponse = responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);
                }
            }
        } catch (IOException e) {
            log.error("", e);
            transactionLogger.flush();
            auditLogger.flush();
        }

        return new OcspResponseInformation(ocspResponse, maxAge);

    }

    public void setCanlog(boolean canLog) {
        CanLogCache.INSTANCE.setCanLog(canLog);
    }

    /**
     * Method that checks with ProbeableErrorHandler if an error has happened since a certain time. Uses reflection to call ProbeableErrorHandler
     * because it is dependent on JBoss log4j logging, which is not available on other application servers.
     * 
     * @param startTime
     * @return true if an error has occurred since startTime
     */
    private boolean hasErrorHandlerFailedSince(Date startTime) {
        boolean result = true; // Default true. If something goes wrong we will fail
        result = ProbableErrorHandler.hasFailedSince(startTime);
        if (result) {
            log.error("Audit and/or account logging failed since " + startTime);
        }
        return result;
    }

    /**
     * This method exists solely to avoid code duplication when error handling in getOcspResponse.
     * 
     * @param responseGenerator A OCSPRespBuilder for generating a response with state INTERNAL_ERROR.
     * @param transactionLogger The TransactionLogger for this call.
     * @param auditLogger The AuditLogger for this call.
     * @param e The thrown exception.
     * @return a response with state INTERNAL_ERROR.
     * @throws OCSPException if generation of the response failed.
     */
    private OCSPResp processDefaultError(OCSPRespBuilder responseGenerator, TransactionLogger transactionLogger, AuditLogger auditLogger,
            Throwable e) throws OCSPException {
        transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
        log.error(errMsg, e);

        transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
        transactionLogger.writeln();
        auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
        return responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null); // RFC 2560: responseBytes are not set on error.
    }

    /**
     * This method takes byte array and translates it onto a OCSPReq class.
     * 
     * @param authenticationToken An authentication token needed to perform validation.
     * @param request the byte array in question.
     * @param remoteAddress The remote address of the HttpRequest associated with this array.
     * @param transactionLogger A transaction logger.
     * @return
     * @throws InvalidKeyException
     * @throws SignRequestException thrown if an unsigned request was processed when system configuration requires that all requests be signed.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignRequestSignatureException
     */
    private OCSPReq translateRequestFromByteArray(byte[] request, String remoteAddress, TransactionLogger transactionLogger)
            throws MalformedRequestException, SignRequestException, SignRequestSignatureException, CertificateException, NoSuchAlgorithmException {

        OCSPReq result = null;
        try {
            result = new OCSPReq(request);
        } catch (IOException e) {
            throw new MalformedRequestException("Could not form OCSP request", e);
        }

        if (result.getRequestorName() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Requestor name is null");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Requestor name is: " + result.getRequestorName().toString());
            }
            transactionLogger.paramPut(TransactionLogger.REQ_NAME, result.getRequestorName().toString());
        }

        /**
         * check the signature if contained in request. if the request does not contain a signature and the servlet is configured in the way the a
         * signature is required we send back 'sigRequired' response.
         */
        if (log.isDebugEnabled()) {
            log.debug("Incoming OCSP request is signed : " + result.isSigned());
        }
        if (result.isSigned()) {
            X509Certificate signercert = checkRequestSignature(remoteAddress, result);
            String signercertIssuerName = CertTools.getIssuerDN(signercert);
            BigInteger signercertSerNo = CertTools.getSerialNumber(signercert);
            String signercertSubjectName = CertTools.getSubjectDN(signercert);

            transactionLogger.paramPut(TransactionLogger.SIGN_ISSUER_NAME_DN, signercertIssuerName);
            transactionLogger.paramPut(TransactionLogger.SIGN_SERIAL_NO, signercert.getSerialNumber().toByteArray());
            transactionLogger.paramPut(TransactionLogger.SIGN_SUBJECT_NAME, signercertSubjectName);
            transactionLogger.paramPut(PatternLogger.REPLY_TIME, TransactionLogger.REPLY_TIME);

            if (OcspConfiguration.getEnforceRequestSigning()) {
                // If it verifies OK, check if it is revoked
                final CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(signercert),
                        CertTools.getSerialNumber(signercert));
                /*
                 * If rci == null it means the certificate does not exist in database, we then treat it as ok, because it may be so that only revoked
                 * certificates is in the (external) OCSP database.
                 */
                if (status.equals(CertificateStatus.REVOKED)) {
                    String serno = signercertSerNo.toString(16);
                    String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.revoked", signercertSubjectName, signercertIssuerName, serno);
                    log.info(infoMsg);
                    throw new SignRequestSignatureException(infoMsg);
                }

                if (OcspConfiguration.getRestrictSignatures()) {
                    DirectoryCache.INSTANCE.loadTrustDir();
                    switch (OcspConfiguration.getRestrictSignaturesByMethod()) {
                    case OcspConfiguration.RESTRICTONSIGNER:
                        if (!checkCertInList(signercert, DirectoryCache.INSTANCE.getTrustedReqSigSigners())) {
                            String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName,
                                    signercertSerNo.toString(16));
                            log.info(infoMsg);
                            throw new SignRequestSignatureException(infoMsg);
                        }
                        break;
                    case OcspConfiguration.RESTRICTONISSUER:
                        X509Certificate signerca = certificateStoreSession.findLatestX509CertificateBySubject(signercertIssuerName);
                        if ((signerca == null) || (!checkCertInList(signerca, DirectoryCache.INSTANCE.getTrustedReqSigIssuers()))) {
                            String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName,
                                    signercertSerNo.toString(16));
                            log.info(infoMsg);
                            throw new SignRequestSignatureException(infoMsg);
                        }
                        break;
                    default:
                        // There must be an internal error. We do not want to send a response, just to be safe.
                        throw new OcspFailureException("m_reqRestrictMethod=" + OcspConfiguration.getRestrictSignaturesByMethod());

                    }
                }
            }
        } else {
            if (OcspConfiguration.getEnforceRequestSigning()) {
                // Signature required
                throw new SignRequestException("Signature required");
            }
        }

        return result;
    }

    private BasicOCSPRespBuilder createOcspResponseGenerator(OCSPReq req, X509Certificate respondercert, int respIdType) throws OCSPException,
            NotSupportedException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        BasicOCSPRespBuilder res = null;
        if (respIdType == OcspConfiguration.RESPONDERIDTYPE_NAME) {
            res = new BasicOCSPRespBuilder(new JcaRespID(respondercert.getSubjectX500Principal()));
        } else {
            res = new JcaBasicOCSPRespBuilder(respondercert.getPublicKey(), SHA1DigestCalculator.buildSha1Instance());
        }
        if (req.hasExtensions()) {
            Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            //X509Extension ext = reqexts.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            if (null != ext) {
                // log.debug("Found extension AcceptableResponses");
                ASN1OctetString oct = ext.getExtnValue();
                try {
                    ASN1Sequence seq = ASN1Sequence.getInstance(new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject());
                    @SuppressWarnings("unchecked")
                    Enumeration<ASN1ObjectIdentifier> en = seq.getObjects();
                    boolean supportsResponseType = false;
                    while (en.hasMoreElements()) {
                        ASN1ObjectIdentifier oid = en.nextElement();
                        // log.debug("Found oid: "+oid.getId());
                        if (oid.equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                            // This is the response type we support, so we are happy! Break the loop.
                            supportsResponseType = true;
                            log.debug("Response type supported: " + oid.getId());
                            continue;
                        }
                    }
                    if (!supportsResponseType) {
                        throw new NotSupportedException("Required response type not supported, this responder only supports id-pkix-ocsp-basic.");
                    }
                } catch (IOException e) {
                }
            }
        }
        return res;
    }

    /**
     * Checks the signature on an OCSP request and checks that it is signed by an allowed CA. Does not check for revocation of the signer certificate
     * 
     * @param clientRemoteAddr The IP address or host name of the remote client that sent the request, can be null.
     * @param req The signed OCSPReq
     * @return X509Certificate which is the certificate that signed the OCSP request
     * @throws SignRequestSignatureException if signature verification fail, or if the signing certificate is not authorized
     * @throws SignRequestException if there is no signature on the OCSPReq
     * @throws OCSPException if the request can not be parsed to retrieve certificates
     * @throws NoSuchProviderException if the BC provider is not installed
     * @throws CertificateException if the certificate can not be parsed
     * @throws NoSuchAlgorithmException if the certificate contains an unsupported algorithm
     * @throws InvalidKeyException if the certificate, or CA key is invalid
     */
    private X509Certificate checkRequestSignature(String clientRemoteAddr, OCSPReq req) throws SignRequestException, SignRequestSignatureException,
            CertificateException, NoSuchAlgorithmException {

        X509Certificate signercert = null;

        if (!req.isSigned()) {
            String infoMsg = intres.getLocalizedMessage("ocsp.errorunsignedreq", clientRemoteAddr);
            log.info(infoMsg);
            throw new SignRequestException(infoMsg);
        }
        // Get all certificates embedded in the request (probably a certificate chain)
        try {
            X509CertificateHolder[] certs = req.getCerts();
            
            
            // Set, as a try, the signer to be the first certificate, so we have a name to log...
            String signer = null;
            if (certs.length > 0) {
                signer = CertTools.getSubjectDN(certificateConverter.getCertificate(certs[0]));
            }

            // We must find a certificate to verify the signature with...
            boolean verifyOK = false;
            for (int i = 0; i < certs.length; i++) {
                X509Certificate certificate = certificateConverter.getCertificate(certs[i]);
                try {
                    if (req.isSignatureValid(new JcaContentVerifierProviderBuilder().build(certificate.getPublicKey()))) {
                        signercert = certificate;
                        signer = CertTools.getSubjectDN(signercert);
                        Date now = new Date();
                        String signerissuer = CertTools.getIssuerDN(signercert);
                        String infoMsg = intres.getLocalizedMessage("ocsp.infosigner", signer);
                        log.info(infoMsg);
                        verifyOK = true;
                        /*
                         * Also check that the signer certificate can be verified by one of the CA-certificates that we answer for
                         */

                        X509Certificate signerca = certificateStoreSession.findLatestX509CertificateBySubject(CertTools.getIssuerDN(certificate));
                        String subject = signer;
                        String issuer = signerissuer;
                        if (signerca != null) {
                            try {
                                signercert.verify(signerca.getPublicKey());
                                if (log.isDebugEnabled()) {
                                    log.debug("Checking validity. Now: " + now + ", signerNotAfter: " + signercert.getNotAfter());
                                }
                                CertTools.checkValidity(signercert, now);
                                // Move the error message string to the CA cert
                                subject = CertTools.getSubjectDN(signerca);
                                issuer = CertTools.getIssuerDN(signerca);
                                CertTools.checkValidity(signerca, now);
                            } catch (SignatureException e) {
                                infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
                                log.info(infoMsg);
                                verifyOK = false;
                            } catch (InvalidKeyException e) {
                                infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
                                log.info(infoMsg);
                                verifyOK = false;
                            } catch (CertificateNotYetValidException e) {
                                infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certnotyetvalid", subject, issuer, e.getMessage());
                                log.info(infoMsg);
                                verifyOK = false;
                            } catch (CertificateExpiredException e) {
                                infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certexpired", subject, issuer, e.getMessage());
                                log.info(infoMsg);
                                verifyOK = false;
                            }
                        } else {
                            infoMsg = intres.getLocalizedMessage("ocsp.infosigner.nocacert", signer, signerissuer);
                            log.info(infoMsg);
                            verifyOK = false;
                        }
                        break;
                    }
                } catch (OperatorCreationException e) {
                    // Very fatal error
                    throw new EJBException("Can not create Jca content signer: ", e);
                }
            }
            if (!verifyOK) {
                String errMsg = intres.getLocalizedMessage("ocsp.errorinvalidsignature", signer);
                log.info(errMsg);
                throw new SignRequestSignatureException(errMsg);
            }
        } catch (OCSPException e) {
            throw new CryptoProviderException("BouncyCastle was not initialized properly.", e);
        } catch (NoSuchProviderException e) {
            throw new CryptoProviderException("BouncyCastle was not found as a provider.", e);
        }

        return signercert;
    }

    /**
     * Checks to see if a certificate is in a list of certificate. Comparison is made on SerialNumber
     * 
     * @param cert the certificate to look for
     * @param trustedCerts the list (Hashtable) to look in
     * @return true if cert is in trustedCerts, false otherwise
     */
    private boolean checkCertInList(X509Certificate cert, Map<String, X509Certificate> trustedCerts) {
        String key = cert.getIssuerDN() + ";" + cert.getSerialNumber().toString(16);
        return trustedCerts.get(key) != null;
    }

    /**
     * returns a Map of responseExtensions to be added to the BacisOCSPResponseGenerator with <code>
     * X509Extensions exts = new X509Extensions(table);
     * basicRes.setResponseExtensions(responseExtensions);
     * </code>
     * 
     * @param req OCSPReq
     * @return a HashMap, can be empty but not null
     */
    private Hashtable<ASN1ObjectIdentifier, Extension> getStandardResponseExtensions(OCSPReq req) {
        Hashtable<ASN1ObjectIdentifier, Extension> result = new Hashtable<ASN1ObjectIdentifier, Extension>();
        if (req.hasExtensions()) {
            // Table of extensions to include in the response
            Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (null != ext) {
                result.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
            }
        }
        return result;
    }

    private BasicOCSPResp signOcspResponse(OCSPReq req, List<OCSPResponseItem> responseList, Extensions exts,
            final X509Certificate[] signerChain, final PrivateKey privateKey, String privateKeyProvider) throws CryptoTokenOfflineException {

        final X509Certificate[] certChain = Arrays.asList(signerChain).toArray(new X509Certificate[0]);
        final X509Certificate signerCert = certChain[0];
        final String sigAlgs = OcspConfiguration.getSignatureAlgorithm();

        final PublicKey pk = signerCert.getPublicKey();
        final String sigAlg = getSigningAlgFromAlgSelection(sigAlgs, pk);
        if (log.isDebugEnabled()) {
            log.debug("Signing algorithm: " + sigAlg);
        }
        final boolean includeChain = OcspConfiguration.getIncludeCertChain();
        if (log.isDebugEnabled()) {
            log.debug("Include chain: " + includeChain);
        }
        final X509Certificate[] chain;
        if (includeChain) {
            chain = certChain;
        } else {
            chain = new X509Certificate[1];
            chain[0] = signerCert;
        }
        try {
            final int respIdType = OcspConfiguration.getResponderIdType();
            final BasicOCSPResp ocspresp = generateBasicOcspResp(req, exts, responseList, sigAlg, signerCert, privateKey, privateKeyProvider, chain,
                    respIdType);

            // Now we can use the returned OCSPServiceResponse to get private key and cetificate chain to sign the ocsp response
            if (log.isDebugEnabled()) {
                Collection<X509Certificate> coll = Arrays.asList(chain);
                log.debug("Cert chain for OCSP signing is of size " + coll.size());
            }

            if (isCertificateValid(signerCert)) {
                return ocspresp;
            } else {
                throw new OcspFailureException("Response was not validly signed.");
            }
        } catch (OCSPException ocspe) {
            throw new OcspFailureException(ocspe);
        } catch (NoSuchProviderException nspe) {
            throw new OcspFailureException(nspe);
        } catch (NotSupportedException e) {
            log.info("OCSP Request type not supported: ", e);
            throw new OcspFailureException(e);
        } catch (IllegalArgumentException e) {
            log.error("IllegalArgumentException: ", e);
            throw new OcspFailureException(e);
        }
    }

    private BasicOCSPResp generateBasicOcspResp(OCSPReq ocspRequest, Extensions exts, List<OCSPResponseItem> responses, String sigAlg,
            X509Certificate signerCert, PrivateKey signerKey, String provider, X509Certificate[] chain, int respIdType) throws NotSupportedException,
            OCSPException, NoSuchProviderException, CryptoTokenOfflineException {
        BasicOCSPResp returnval = null;
        BasicOCSPRespBuilder basicRes = null;
        basicRes = createOcspResponseGenerator(ocspRequest, signerCert, respIdType);
        if (responses != null) {
            for (OCSPResponseItem item : responses) {
                basicRes.addResponse(item.getCertID(), item.getCertStatus(), item.getThisUpdate(), item.getNextUpdate(), null);
            }
        }
        if (exts != null) {
            @SuppressWarnings("rawtypes")
            Enumeration oids = exts.oids();
            if (oids.hasMoreElements()) {
                basicRes.setResponseExtensions(exts);
            }
        }

        /*
         * The below code breaks the EJB standard by creating its own thread pool and creating a single thread (of the HsmResponseThread 
         * type). The reason for this is that the HSM may deadlock when requesting an OCSP response, which we need to guard against. Since 
         * there is no way of performing this action within the EJB3.0 standard, we are consciously creating threads here. 
         * 
         * Note that this does in no way break the spirit of the EJB standard, which is to not interrupt EJB's transaction handling by 
         * competing with its own thread pool, since these operations have no database impact.
         */

        final ExecutorService service = Executors.newFixedThreadPool(1);
        final Future<BasicOCSPResp> task = service.submit(new HsmResponseThread(basicRes, sigAlg, signerKey, chain, provider));

        try {
            returnval = task.get(HsmResponseThread.HSM_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new Error("OCSP response retrieval was interrupted while running. This should not happen", e);
        } catch (ExecutionException e) {
            throw new OcspFailureException("Failure encountered while retrieving OCSP response.", e);
        } catch (TimeoutException e) {
            throw new CryptoTokenOfflineException("HSM timed out while trying to get OCSP response", e);
        }

        if (log.isDebugEnabled()) {
            log.debug("Signing OCSP response with OCSP signer cert: " + signerCert.getSubjectDN().getName());
            RespID respId = null;
            if (respIdType == OcspConfiguration.RESPONDERIDTYPE_NAME) {
                respId = new JcaRespID(signerCert.getSubjectX500Principal());
            } else {
                respId = new JcaRespID(signerCert.getPublicKey(), SHA1DigestCalculator.buildSha1Instance());
            }
            if (!returnval.getResponderId().equals(respId)) {
                log.error("Response responderId does not match signer certificate responderId!");
            }      
            boolean verify;
            try {
                verify = returnval.isSignatureValid(new JcaContentVerifierProviderBuilder().build(signerCert.getPublicKey()));
            } catch (OperatorCreationException e) {
                // Very fatal error
                throw new EJBException("Can not create Jca content signer: ", e);
            }
            if (verify) {
                log.debug("The OCSP response is verifying.");
            } else {
                log.error("The response is NOT verifying!");
            }
        }
        return returnval;
    }

    /**
     * Returns a signing algorithm to use selecting from a list of possible algorithms.
     * 
     * @param sigalgs the list of possible algorithms, ;-separated. Example "SHA1WithRSA;SHA1WithECDSA".
     * @param pk public key of signer, so we can choose between RSA, DSA and ECDSA algorithms
     * @return A single algorithm to use Example: SHA1WithRSA, SHA1WithDSA or SHA1WithECDSA
     */
    private static String getSigningAlgFromAlgSelection(String sigalgs, PublicKey pk) {
        String sigAlg = null;
        String[] algs = StringUtils.split(sigalgs, ';');
        for (int i = 0; i < algs.length; i++) {
            if (AlgorithmTools.isCompatibleSigAlg(pk, algs[i])) {
                sigAlg = algs[i];
                break;
            }
        }
        log.debug("Using signature algorithm for response: " + sigAlg);
        return sigAlg;
    }

    /**
     * Checks if a certificate is valid Does also print a WARN if the certificate is about to expire.
     * 
     * @param signerCert the certificate to be tested
     * @return true if the certificate is valid
     */
    private static boolean isCertificateValid(X509Certificate signerCert) {
        try {
            signerCert.checkValidity();
        } catch (CertificateExpiredException e) {
            log.error(intres.getLocalizedMessage("ocsp.errorcerthasexpired", signerCert.getSerialNumber(), signerCert.getIssuerDN()));
            return false;
        } catch (CertificateNotYetValidException e) {
            log.error(intres.getLocalizedMessage("ocsp.errornotyetvalid", signerCert.getSerialNumber(), signerCert.getIssuerDN()));
            return false;
        }
        final long warnBeforeExpirationTime = OcspConfiguration.getWarningBeforeExpirationTime();
        if (warnBeforeExpirationTime < 1) {
            return true;
        }
        final Date warnDate = new Date(new Date().getTime() + warnBeforeExpirationTime);
        try {
            signerCert.checkValidity(warnDate);
        } catch (CertificateExpiredException e) {
            log.warn(intres.getLocalizedMessage("ocsp.warncertwillexpire", signerCert.getSerialNumber(), signerCert.getIssuerDN(),
                    signerCert.getNotAfter()));
        } catch (CertificateNotYetValidException e) {
            throw new Error("This should never happen.", e);
        }
        if (!log.isDebugEnabled()) {
            return true;
        }
        log.debug("Time for \"certificate will soon expire\" not yet reached. You will be warned after: "
                + new Date(signerCert.getNotAfter().getTime() - warnBeforeExpirationTime));
        return true;
    }
}
