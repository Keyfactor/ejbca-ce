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
package org.ejbca.core.ejb.ocsp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStatusHolder;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.cache.OcspConfigurationCache;
import org.cesecore.certificates.ocsp.cache.OcspDataConfigCache;
import org.cesecore.certificates.ocsp.cache.OcspDataConfigCacheEntry;
import org.cesecore.certificates.ocsp.cache.OcspExtensionsCache;
import org.cesecore.certificates.ocsp.cache.OcspRequestSignerStatusCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.certificates.ocsp.exception.CryptoProviderException;
import org.cesecore.certificates.ocsp.exception.IllegalNonceException;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.ocsp.extension.OCSPExtension;
import org.cesecore.certificates.ocsp.extension.OCSPExtensionType;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.PatternLogger;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keybind.impl.OcspKeyBinding.ResponderIdType;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.util.CeSecoreNameStyle;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.log.ProbableErrorHandler;
import org.cesecore.util.provider.EkuPKIXCertPathChecker;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.ca.publisher.PublisherException;

/**
 * This SSB generates OCSP responses. 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspResponseGeneratorSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class OcspResponseGeneratorSessionBean implements OcspResponseGeneratorSessionRemote, OcspResponseGeneratorSessionLocal {

    /** Max size of a request is 100000 bytes */
    private static final int MAX_REQUEST_SIZE = 100000;
    /** Timer identifiers */
    private static final int TIMERID_OCSPSIGNINGCACHE = 1;

    private static final Logger log = Logger.getLogger(OcspResponseGeneratorSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();
    
    private static volatile ExecutorService service = Executors.newCachedThreadPool();
    
    @Resource
    private SessionContext sessionContext;
    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private OcspDataSessionLocal ocspDataSession;
    
    @EJB
    private PublisherSessionLocal publisherSession;

    private JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();

    /** For tests only */
    protected void setMockedCaSession(final CaSessionLocal caSession) { this.caSession = caSession; }
    protected void setMockedCertificateStoreSession(final CertificateStoreSessionLocal certificateStoreSession) { this.certificateStoreSession = certificateStoreSession; }
    protected void setMockedCryptoTokenSession(final CryptoTokenSessionLocal cryptoTokenSession) { this.cryptoTokenSession = cryptoTokenSession; }
    protected void setMockedInternalKeyBindingDataSession(final InternalKeyBindingDataSessionLocal internalKeyBindingDataSession) { this.internalKeyBindingDataSession = internalKeyBindingDataSession; }
    protected void setMockedGlobalConfigurationSession(final GlobalConfigurationSessionLocal globalConfigurationSession) { this.globalConfigurationSession = globalConfigurationSession; }
    protected void setMockedTimerService(final TimerService timerService) { this.timerService = timerService; }

    @PostConstruct
    public void init() {
        timerService = sessionContext.getTimerService();
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void initTimers() {
        // Reload OCSP signing cache, and cancel/create timers if there are no timers or if the cache is empty (probably a fresh startup)
        if (getTimerCount(TIMERID_OCSPSIGNINGCACHE)==0 || OcspSigningCache.INSTANCE.getEntries().isEmpty()){
            reloadOcspSigningCache();
        } else {
            log.info("Not initing OCSP reload timers, there are already some.");
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void reloadOcspExtensionsCache() {
        OcspExtensionsCache.INSTANCE.reloadCache();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void clearCTFailFastCache() {
        final CertificateTransparency ct = CertificateTransparencyFactory.getInstance();
        if (ct != null) {
            ct.clearCaches();
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void clearOcspRequestSignerRevocationStatusCache() {
        OcspRequestSignerStatusCache.INSTANCE.flush();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void reloadOcspSigningCache() {
        if (log.isTraceEnabled()) {
            log.trace(">reloadOcspSigningCache");
        }
        // Cancel any waiting timers of this type
        cancelTimers(TIMERID_OCSPSIGNINGCACHE);
        
        try {
            // Verify card key holder
            GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            OcspSigningCache.INSTANCE.stagingStart();
            OcspDataConfigCache.INSTANCE.stagingStart();
            try {
                // Populate OcspSigningCache
                // Add all potential CA's as OCSP responders to the staging area
                for (final Integer caId : caSession.getAllCaIds()) {
                    final List<X509Certificate> caCertificateChain = new ArrayList<>();

                    final CAInfo caInfo = caSession.getCAInfoInternal(caId);
                    if (caInfo == null || caInfo.getCAType() == CAInfo.CATYPE_CVC
                            || caInfo.getCAType() == CAInfo.CATYPE_CITS) {
                        // Bravely ignore OCSP for CVC CAs
                        continue;
                    }

                    boolean preProduceOcspResponse = false;
                    boolean storeOcspResponseOnDemand = false;
                    boolean isMsCaCompatible = false;
                    // Should always be true since CVCAs are ignored here. Better safe than sorry though.
                    if (caInfo instanceof X509CAInfo) {
                        preProduceOcspResponse = ((X509CAInfo) caInfo).isDoPreProduceOcspResponses();
                        storeOcspResponseOnDemand = ((X509CAInfo) caInfo).isDoStoreOcspResponsesOnDemand();
                        isMsCaCompatible = ((X509CAInfo) caInfo).isMsCaCompatible();
                    }

                    if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                        //Cache active CAs as signers
                        if (log.isDebugEnabled()) {
                            log.debug("Processing X509 CA " + caInfo.getName() + " (" + caInfo.getCAId() + ").");
                        }
                        final CAToken caToken = caInfo.getCAToken();
                        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
                        if (cryptoToken == null) {
                            log.info("Excluding CA with id " + caId + " for OCSP signing consideration due to missing CryptoToken.");
                            continue;
                        }
                        
                        for (final Certificate certificate : caInfo.getCertificateChain()) {
                            caCertificateChain.add((X509Certificate) certificate);
                        }
                        
                        if (isMsCaCompatible) {
                            OcspDataConfigCache.INSTANCE.setCaModeCompatiblePresent(true);
                            List<Certificate> activeCaCertificates = certificateStoreSession.findCertificatesBySubjectAndIssuer(caInfo.getSubjectDN(),
                                    caInfo.getLatestSubjectDN(), true);

                            for (Certificate cert : activeCaCertificates) {
                                String signKeyAlias = getSignKeyAliasFromSubjectKeyId(cryptoToken, getAuthorityKeyIdentifier((X509Certificate) cert));
                                final PrivateKey privateKey;

                                try {
                                    privateKey = cryptoToken.getPrivateKey(signKeyAlias);
                                    if (privateKey == null) {
                                        log.warn(
                                                "Referenced private key with alias " + signKeyAlias + " does not exist. Ignoring CA with id " + caId);
                                        continue;
                                    }
                                } catch (CryptoTokenOfflineException e) {
                                    log.warn("Referenced private key with alias " + signKeyAlias
                                            + " could not be used. CryptoToken is off-line for CA with id " + caId + ": " + e.getMessage());
                                    continue;
                                }

                                // Replace the current leaf certificate in the ca chain with the corresponding one from DB!
                                caCertificateChain.remove(0);
                                caCertificateChain.add((X509Certificate) cert);
                                
                                final String signatureProviderName = cryptoToken.getSignProviderName();
                                if (!caCertificateChain.isEmpty()) {
                                    generateOcspSigningCacheEntries(caCertificateChain, signatureProviderName, privateKey, ocspConfiguration);
                                } else {
                                    log.warn("CA with ID " + caId
                                            + " appears to lack a certificate in the database. This may be a serious error if not in a test environment.");
                                }
                            }
                        } else {
                            final String keyPairAlias;
                            try {
                                keyPairAlias = caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                            } catch (CryptoTokenOfflineException e) {
                                log.warn("Referenced private key with purpose " + CATokenConstants.CAKEYPURPOSE_CERTSIGN
                                        + " could not be used. CryptoToken is off-line for CA with id " + caId + ": " + e.getMessage());
                                continue;
                            }
                            final PrivateKey privateKey;
                            try {
                                privateKey = cryptoToken.getPrivateKey(keyPairAlias);
                            } catch (CryptoTokenOfflineException e) {
                                log.warn("Referenced private key with alias " + keyPairAlias
                                        + " could not be used. CryptoToken is off-line for CA with id " + caId + ": " + e.getMessage());
                                continue;
                            }
                            if (privateKey == null) {
                                log.warn("Referenced private key with alias " + keyPairAlias + " does not exist. Ignoring CA with id " + caId);
                                continue;
                            }
                            final String signatureProviderName = cryptoToken.getSignProviderName();
                            if (!caCertificateChain.isEmpty()) {
                                generateOcspSigningCacheEntries(caCertificateChain, signatureProviderName, privateKey, ocspConfiguration);
                                generateOcspConfigCacheEntry(caCertificateChain.get(0), caId, preProduceOcspResponse, storeOcspResponseOnDemand, isMsCaCompatible);

                            } else {
                                log.warn("CA with ID " + caId
                                        + " appears to lack a certificate in the database. This may be a serious error if not in a test environment.");
                            }
                        }
                    } else if (caInfo.getStatus() == CAConstants.CA_EXTERNAL) {
                        // If set, all external CA's without a keybinding (set below) will be responded to by the default responder. 
                        for (final Certificate certificate : caInfo.getCertificateChain()) {
                            caCertificateChain.add((X509Certificate) certificate);
                        }
                        final CertificateStatus caCertificateStatus = getRevocationStatusWhenCasPrivateKeyIsCompromised(caCertificateChain.get(0),
                                false);
                        // Check if CA cert has been revoked (only key compromise as returned above). Always make this check, even if this CA has an OCSP signing certificate, because
                        // signing will still fail even if the signing cert is valid. 
                        if (caCertificateStatus.equals(CertificateStatus.REVOKED)) {
                            log.info("External CA with subject DN '" + CertTools.getSubjectDN(caCertificateChain.get(0)) + "' and serial number "
                                    + CertTools.getSerialNumber(caCertificateChain.get(0)) + " has a revoked certificate with reason "
                                    + caCertificateStatus.revocationReason + ".");
                        }
                        //Check if CA cert is expired
                        if (!CertTools.isCertificateValid(caCertificateChain.get(0), false)) {
                            log.info("External CA with subject DN '" + CertTools.getSubjectDN(caCertificateChain.get(0)) + "' and serial number "
                                    + CertTools.getSerialNumber(caCertificateChain.get(0)) + " has an expired certificate with expiration date "
                                    + CertTools.getNotAfter(caCertificateChain.get(0)) + ".");
                        }
                        //Add an entry with just a chain and nothing else
                        OcspSigningCache.INSTANCE.stagingAdd(new OcspSigningCacheEntry(caCertificateChain.get(0), caCertificateStatus, null, null,
                                null, null, null, ocspConfiguration.getOcspResponderIdType()));
                        OcspDataConfigCache.INSTANCE.stagingAdd(new OcspDataConfigCacheEntry(caCertificateChain.get(0), caId, preProduceOcspResponse,
                                storeOcspResponseOnDemand, isMsCaCompatible));
                    } else if (caInfo.getStatus() == CAConstants.CA_EXPIRED && preProduceOcspResponse) {
                        // We need this entry to respond with stored "Final OCSP Response" for expired CA (eIDAS specific: EN 319 411-2)
                        for (final Certificate certificate : caInfo.getCertificateChain()) {
                            caCertificateChain.add((X509Certificate) certificate);
                        }
                        if (!caCertificateChain.isEmpty()) {
                            OcspDataConfigCache.INSTANCE.stagingAdd(new OcspDataConfigCacheEntry(caCertificateChain.get(0), caId,
                                    preProduceOcspResponse, storeOcspResponseOnDemand, isMsCaCompatible));
                        } else {
                            log.warn("Expired CA with ID " + caId
                                    + " appears to lack a certificate in the database. This will prevent serving of Final OCSP Responses");
                        }
                    }
                }
                // Add all potential InternalKeyBindings as OCSP responders to the staging area, overwriting CA entries from before
                for (final int internalKeyBindingId : internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
                    final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
                    if (log.isDebugEnabled()) {
                        log.debug("Processing " + ocspKeyBinding.getName() + " (" + ocspKeyBinding.getId() + ")");
                    }
                    if (!ocspKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Ignoring OcspKeyBinding since it is not active.");
                        }
                        continue;
                    }
                    final X509Certificate ocspSigningCertificate = (X509Certificate) certificateStoreSession
                            .findCertificateByFingerprint(ocspKeyBinding.getCertificateId());
                    if (ocspSigningCertificate == null) {
                        log.warn("OCSP signing certificate with referenced fingerprint " + ocspKeyBinding.getCertificateId()
                                + " does not exist. Ignoring internalKeyBinding with id " + ocspKeyBinding.getId());
                        continue;
                    }
                    //Make the same check as above 
                    if (certificateStoreSession
                            .getStatus(CertTools.getIssuerDN(ocspSigningCertificate), CertTools.getSerialNumber(ocspSigningCertificate))
                            .equals(CertificateStatus.REVOKED)) {
                        log.warn("OCSP Responder certificate with subject DN '" + CertTools.getSubjectDN(ocspSigningCertificate)
                                + "' and serial number " + CertTools.getSerialNumber(ocspSigningCertificate) + " is revoked.");
                    }
                    //Check if signing cert is expired
                    if (!CertTools.isCertificateValid(ocspSigningCertificate, true)) {
                        log.warn("OCSP Responder certificate with subject DN '" + CertTools.getSubjectDN(ocspSigningCertificate)
                                + "' and serial number " + CertTools.getSerialNumber(ocspSigningCertificate) + " is expired.");
                    }

                    OcspSigningCacheEntry ocspSigningCacheEntry = makeOcspSigningCacheEntry(ocspSigningCertificate, ocspKeyBinding);
                    if (ocspSigningCacheEntry != null) {
                        addSignResponseOnBehalfCasToCacheEntry(ocspSigningCacheEntry, ocspKeyBinding);
                        OcspSigningCache.INSTANCE.stagingAdd(ocspSigningCacheEntry);
                    }
                }
                OcspSigningCache.INSTANCE.stagingCommit(ocspConfiguration.getOcspDefaultResponderReference());
                OcspDataConfigCache.INSTANCE.stagingCommit();
            } finally {
                OcspSigningCache.INSTANCE.stagingRelease();
            }
        } finally {
            // Schedule a new timer of this type
            addTimer(OcspConfiguration.getSigningCertsValidTimeInMilliseconds(), TIMERID_OCSPSIGNINGCACHE);
        }
    }
    
    private void addSignResponseOnBehalfCasToCacheEntry(OcspSigningCacheEntry ocspSigningCacheEntry, 
                                                                            OcspKeyBinding ocspKeyBinding) {
        Set<CertificateID> signedBehalfOfCaIds = ocspSigningCacheEntry.getSignedBehalfOfCaIds();
        Map<CertificateID, X509Certificate> signedBehalfOfCaCerticates = 
                                                        ocspSigningCacheEntry.getSignedBehalfOfCaCerticates();
        Map<CertificateID, CertificateStatus> signedBehalfOfCaStatus = 
                                                            ocspSigningCacheEntry.getSignedBehalfOfCaStatus();
        
        List<CertificateID> willSignForCaId;
        for(InternalKeyBindingTrustEntry signOnBehalfEntry: ocspKeyBinding.getSignOcspResponseOnBehalf()) {
            CAData caData = caSession.findById(signOnBehalfEntry.getCaId());
            if(caData==null) {
                log.debug("CA with id might have been deleted (caId): " + signOnBehalfEntry.getCaId());
                continue;
            }
            
            boolean preProduceOcspResponse = false;
            if (caData.getCA().getCAInfo() instanceof X509CAInfo) {
                preProduceOcspResponse = ((X509CAInfo) caData.getCA().getCAInfo()).isDoPreProduceOcspResponses();
            } else {
                continue;
            }
            
            if(caData.getStatus()!=CAConstants.CA_ACTIVE && caData.getStatus()!=CAConstants.CA_EXTERNAL && 
                    !(caData.getStatus() == CAConstants.CA_EXPIRED && preProduceOcspResponse)) {
                log.debug("OCSP sign on behalf is allowed only for active, "
                        + "external CAs or expired CAs with preproduced OCSP response (caId): "
                                                                        + signOnBehalfEntry.getCaId());
                continue;
            }
            
            X509Certificate caCert = (X509Certificate) caData.getCA().getCACertificate();
            willSignForCaId = OcspSigningCache.getCertificateIDFromCertificate(caCert);
            signedBehalfOfCaIds.addAll(willSignForCaId);
            CertificateStatus certificateStatus = getRevocationStatusWhenCasPrivateKeyIsCompromised(caCert, true);
            
            for(CertificateID certId: willSignForCaId) {
                signedBehalfOfCaStatus.put(certId, certificateStatus);
                signedBehalfOfCaCerticates.put(certId, caCert);
            }
            
        }
        
        if(!signedBehalfOfCaIds.isEmpty()) {
            ocspSigningCacheEntry.refreshInternalMappings();
        }
    }
    
    private byte[] getAuthorityKeyIdentifier(X509Certificate certificate) {
        byte[] fullExtValue = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        byte[] extValue = ASN1OctetString.getInstance(fullExtValue).getOctets();
        return AuthorityKeyIdentifier.getInstance(extValue).getKeyIdentifier();
    }
    
    private String getSignKeyAliasFromSubjectKeyId(CryptoToken cryptoToken, byte[] certificateSubjectKeyId) {
        if (log.isDebugEnabled()) {
            log.debug("certSubjectKeyId: " + new String(Hex.encode(certificateSubjectKeyId)));
        }
        try {
            for (String keyAlias : cryptoToken.getAliases()) {
                String subjectKeyId = new String(Hex.encode(KeyTools.createSubjectKeyId(cryptoToken.getPublicKey(keyAlias)).getKeyIdentifier()));
                if (StringUtils.equals(subjectKeyId, new String(Hex.encode(certificateSubjectKeyId)))) {
                    return keyAlias;
                }
            }
        } catch (KeyStoreException | CryptoTokenOfflineException e) {
            throw new IllegalStateException(e);
        }
        throw new IllegalStateException("No key matching Subject Key Id '" + new String(Hex.encode(certificateSubjectKeyId)) + "' found.");
    }
    
    private void generateOcspSigningCacheEntries(List<X509Certificate> caCertificateChain, String signatureProviderName, PrivateKey privateKey,
            GlobalOcspConfiguration ocspConfiguration) {
        X509Certificate caCertificate = caCertificateChain.get(0);
        final CertificateStatus caCertificateStatus = getRevocationStatusWhenCasPrivateKeyIsCompromised(caCertificate, false);

        OcspSigningCache.INSTANCE.stagingAdd(new OcspSigningCacheEntry(caCertificate, caCertificateStatus, caCertificateChain, null, privateKey,
                signatureProviderName, null, ocspConfiguration.getOcspResponderIdType()));
        checkWarnings(caCertificateStatus, caCertificate);
    }

    private void generateOcspConfigCacheEntry(X509Certificate caCertificate, int caId, boolean preProduceOcspResponse, boolean storeOcspResponseOnDemand, boolean isMsCaCompatible) {

        // Build OcspPreProductionConfigCache
        OcspDataConfigCache.INSTANCE.stagingAdd(new OcspDataConfigCacheEntry(caCertificate, caId, preProduceOcspResponse, storeOcspResponseOnDemand, isMsCaCompatible));

    }
    
    private void checkWarnings(CertificateStatus caCertificateStatus, X509Certificate caCertificate) {
        // Check if CA cert has been revoked (only key compromise as returned above). Always make this check, even if this CA has an OCSP signing certificate, because
        // signing will still fail even if the signing cert is valid. Shouldn't happen, but log it just in case.
        if (caCertificateStatus.equals(CertificateStatus.REVOKED)) {
            log.warn("Active CA with subject DN '" + CertTools.getSubjectDN(caCertificate) + "' and serial number "
                    + CertTools.getSerialNumber(caCertificate) + " has a revoked certificate with reason " + caCertificateStatus.revocationReason
                    + ".");
        }
        //Check if CA cert is expired
        if (!CertTools.isCertificateValid(caCertificate, true)) {
            log.warn("Active CA with subject DN '" + CertTools.getSubjectDN(caCertificate) + "' and serial number "
                    + CertTools.getSerialNumber(caCertificate) + " has an expired certificate with expiration date "
                    + CertTools.getNotAfter(caCertificate) + ".");
        }
    }

    /**
     * Constructs an OcspSigningCacheEntry from the given parameters.
     * 
     * @param ocspSigningCertificate The signing certificate associated with the key binding. May be found separately, so given as a separate parameter
     * @param ocspKeyBinding the Key Binding to base the cache entry off of. 
     * @return an OcspSigningCacheEntry, or null if any error was encountered.
     */
    private OcspSigningCacheEntry makeOcspSigningCacheEntry(X509Certificate ocspSigningCertificate, OcspKeyBinding ocspKeyBinding) {
        final List<X509Certificate> caCertificateChain = getCaCertificateChain(ocspSigningCertificate);
        if (caCertificateChain.isEmpty()) {
            log.warn("OcspKeyBinding " + ocspKeyBinding.getName() + " ( " + ocspKeyBinding.getId() + ") has a signing certificate, but no chain and will be ignored.");
            return null;
        }
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ocspKeyBinding.getCryptoTokenId());
        if (cryptoToken == null) {
            log.warn("Referenced CryptoToken with id " + ocspKeyBinding.getCryptoTokenId() + " does not exist. Ignoring OcspKeyBinding with id "
                    + ocspKeyBinding.getId());
            return null;
        }
        final PrivateKey privateKey;
        try {
            privateKey = cryptoToken.getPrivateKey(ocspKeyBinding.getKeyPairAlias());
        } catch (CryptoTokenOfflineException e) {
            log.warn("Referenced private key with alias " + ocspKeyBinding.getKeyPairAlias() + " could not be used. CryptoToken is off-line for OcspKeyBinding with id "+ocspKeyBinding.getId()+": " + e.getMessage());
            return null;
        }
        if (privateKey == null) {
            log.warn("Referenced private key with alias " + ocspKeyBinding.getKeyPairAlias() + " does not exist. Ignoring OcspKeyBinding with id "+ ocspKeyBinding.getId());
            return null;
        }
        final String signatureProviderName = cryptoToken.getSignProviderName();
        if (log.isDebugEnabled()) {
            log.debug("Adding OcspKeyBinding "+ocspKeyBinding.getId()+", "+ocspKeyBinding.getName());
        }
        final CertificateStatus certificateStatus = getRevocationStatusWhenCasPrivateKeyIsCompromised(caCertificateChain.get(0), true);
        OcspKeyBinding.ResponderIdType respIdType;
        if (ResponderIdType.NAME.equals(ocspKeyBinding.getResponderIdType())) {
            respIdType = OcspKeyBinding.ResponderIdType.NAME;
        } else {
            respIdType = OcspKeyBinding.ResponderIdType.KEYHASH;
        }
        return new OcspSigningCacheEntry(caCertificateChain.get(0), certificateStatus, caCertificateChain, ocspSigningCertificate, privateKey,
                signatureProviderName, ocspKeyBinding, respIdType);
    }
    
    /** 
     * RFC 6960 Section 2.7 states that if it is known CA's private key has been compromised, it MAY return the "revoked"
     * state for all certificates issued by that CA.
     * 
     * We interpret this as if the revocation reasons is one of "keyCompromise", "cACompromise" or "aACompromise" we know this.
     * Additionally, if the "unspecified" reason is used we will consider this as a known private key compromise. (Safety first!)
     * 
     * @param caCertificate the X.509 CA certificate to check
     * @param suppressInfo set to true to only do debug logging instead of info logging
     * @return OK or the revocation status that we will use if the CA is revoked (same revocation date, but with reasonCode "cACompromise")
     */
    private CertificateStatus getRevocationStatusWhenCasPrivateKeyIsCompromised(final X509Certificate caCertificate, final boolean suppressInfo) {
        final String issuerDn = CertTools.getIssuerDN(caCertificate);
        final BigInteger serialNumber = CertTools.getSerialNumber(caCertificate);
        final CertificateStatus certificateStatus = certificateStoreSession.getStatus(issuerDn, serialNumber);
        if (certificateStatus.isRevoked()) {
            final String subjectDn = CertTools.getSubjectDN(caCertificate);
            if (certificateStatus.revocationReason == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED ||
                    certificateStatus.revocationReason == RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE ||
                    certificateStatus.revocationReason == RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE ||
                    certificateStatus.revocationReason == RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE) {
                final String msg = "CA certificate Subject DN '" + subjectDn + "', Issuer DN '" + issuerDn + "' and serial number " +
                    serialNumber.toString() + " (0x" + serialNumber.toString(16) +
                    ") is revoked with reason code " +certificateStatus.revocationReason + ". " +
                    "The cACompromise revocation reason will be used for all certs issued by this CA.";
                if (suppressInfo) {
                    log.debug(msg);
                } else {
                    log.info(msg);
                }
                return new CertificateStatus(certificateStatus.toString(), certificateStatus.revocationDate.getTime(),
                        RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, certificateStatus.certificateProfileId);
            }
            final String msg = "CA certificate Subject DN '" + subjectDn + "', Issuer DN '" + issuerDn + "' and serial number " +
                serialNumber.toString() + " (0x" + serialNumber.toString(16) +
                ") is revoked with reason code " +certificateStatus.revocationReason + ". " +
                "Status of individual leaf certificate will still be checked.";
            if (suppressInfo) {
                log.debug(msg);
            } else {
                log.info(msg);
            }
        }
        return CertificateStatus.OK;
    }
    
    private boolean isSelfSigned(final X509Certificate cert) {
        final byte[] aki = CertTools.getAuthorityKeyId(cert);
        final byte[] ski = CertTools.getSubjectKeyId(cert);
        boolean keyIdsAreEqual = false;
        if (aki != null) {
            keyIdsAreEqual = Arrays.equals(aki, ski);
        }
        final Principal sdn = cert.getSubjectDN();
        final Principal idn = cert.getIssuerDN();
        final boolean dNsAreEqual = sdn.equals(idn);
        //AKI can be omitted in self signed certificates, RFC 5280
        if ((aki == null && dNsAreEqual) || keyIdsAreEqual ){
            return true;
        }
        return false;
    }
    
    private X509Certificate findIssuerCa(List<Certificate> certificateList, X509Certificate currentLevelCertificate) {
        List<Certificate> verifiedIssuers = new ArrayList<>();
        Certificate issuer = null;
        final byte[] aki = CertTools.getAuthorityKeyId(currentLevelCertificate);
        for (final Certificate certificate : certificateList) {
            final byte[] ski = CertTools.getSubjectKeyId(certificate);
            if (aki != null && Arrays.equals(aki, ski)) {
                verifiedIssuers.add(certificate);
            }
        }
        for (final Certificate cert : verifiedIssuers) {
            //Find latest issuer cert
            if (issuer == null || CertTools.getNotBefore(cert).after(CertTools.getNotBefore(issuer))) {
                issuer = cert;
            }
        }
        return (X509Certificate) issuer;
    }

    private List<X509Certificate> getCaCertificateChain(final X509Certificate leafCertificate) {
        final List<X509Certificate> caCertificateChain = new ArrayList<>();
        X509Certificate currentLevelCertificate = leafCertificate;
        final Set<String> includedFingerprint = new HashSet<>();
        while (!isSelfSigned(currentLevelCertificate)) {
            final String issuerDn = CertTools.getIssuerDN(currentLevelCertificate);
            final String issuerFingerprint = CertTools.getFingerprintAsString(currentLevelCertificate);
            List<Certificate> resultList = new ArrayList<>();
            resultList = certificateStoreSession.findCertificatesBySubject(issuerDn);
            currentLevelCertificate = findIssuerCa(resultList, currentLevelCertificate);
            if (currentLevelCertificate == null) {
                log.warn("Unable to build certificate chain for OCSP signing certificate with Subject DN '" +
                        CertTools.getSubjectDN(leafCertificate) + "'. CA with Subject DN '" + issuerDn + "' is missing in the database.");
                return Collections.emptyList();
            }
            if (!includedFingerprint.add(issuerFingerprint)) {
                if (log.isDebugEnabled()) {
                    log.debug("Cyclic cross signing detected in '" + issuerDn + "'");
                }
                break;
            }
            caCertificateChain.add(currentLevelCertificate);
        }
        try {
            CertTools.verify(leafCertificate, caCertificateChain, new Date(), new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_OCSPSigning.getId()));
        } catch (CertPathValidatorException e) {
            // Apparently the built chain could not be used to validate the leaf certificate
            // this could happen if the CA keys were renewed, but the subject DN did not change
            log.info("Unable to build a valid certificate chain for OCSP signing certificate with Subject DN '" +
                    CertTools.getSubjectDN(leafCertificate)  + "' and Issuer DN " + CertTools.getIssuerDN(leafCertificate) +
                    "' using the latest CA certificate(s) in the database. Trying to recover from exception: " + e.getMessage());
            final CertificateInfo certificateInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(leafCertificate));
            if(certificateInfo == null) {
                return Collections.emptyList();
            }
            final List<Certificate> chainByFingerPrints = certificateStoreSession.getCertificateChain(certificateInfo);
            if (!chainByFingerPrints.isEmpty()) {
                // Remove the leaf certificate itself
                chainByFingerPrints.remove(0);
            }
            caCertificateChain.clear();
            for (final Certificate current : chainByFingerPrints) {
                if (current instanceof X509Certificate) {
                    caCertificateChain.add((X509Certificate) current);
                } else {
                    log.warn("Unable to build certificate chain for OCSP signing certificate with Subject DN '" +
                            CertTools.getSubjectDN(leafCertificate) + "' and Issuer DN '" + CertTools.getIssuerDN(leafCertificate) +
                            "'. CA certificate chain contains non-X509 certificates.");
                    return Collections.emptyList();
                }
            }
            if (caCertificateChain.isEmpty()) {
                log.warn("Unable to build certificate chain for OCSP signing certificate with Subject DN '" +
                        CertTools.getSubjectDN(leafCertificate) + "' and Issuer DN '" + CertTools.getIssuerDN(leafCertificate) +
                        "''. CA certificate(s) are missing in the database.");
                return Collections.emptyList();
            }
            try {
                CertTools.verify(leafCertificate, caCertificateChain, new Date(), new EkuPKIXCertPathChecker(KeyPurposeId.id_kp_OCSPSigning.getId()));
            } catch (Exception e2) {
                log.warn("Unable to build certificate chain for OCSP signing certificate with Subject DN '" +
                        CertTools.getSubjectDN(leafCertificate) + "' and Issuer DN '" + CertTools.getIssuerDN(leafCertificate) +
                        "''. Found CA certificate(s) cannot be used for validation: " + e2.getMessage());
                return Collections.emptyList();
            }
            log.info("Recovered and managed to build a valid certificate chain for OCSP signing certificate with Subject DN '" +
                    CertTools.getSubjectDN(leafCertificate) + "' and Issuer DN '" + CertTools.getIssuerDN(leafCertificate) +
                    "'.");
        }
        return caCertificateChain;
    }
   
    
      // ECA_10509 No fix available.
//    @Override
//    public void setCanlog(boolean canLog) {
//        CanLogCache.INSTANCE.setCanLog(canLog);
//    }

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
    private OCSPResp processDefaultError(final boolean isPresigning, OCSPRespBuilder responseGenerator, TransactionLogger transactionLogger, AuditLogger auditLogger, Throwable e)
            throws OCSPException {
        if (!isPresigning && transactionLogger.isEnabled()) {
            transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        }
        if (!isPresigning && auditLogger.isEnabled()) {
            auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        }
        String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
        log.error(errMsg, e);
        if (!isPresigning && transactionLogger.isEnabled()) {
            transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
        }
        if (!isPresigning && auditLogger.isEnabled()) {
            auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.INTERNAL_ERROR);
        }
        return responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null); // RFC 2560: responseBytes are not set on error.
    }

    /**
     * Select the preferred OCSP response sigAlg according to RFC6960 Section 4.4.7 in the following order:
     * 
     *    1. Select an algorithm specified as a preferred signature algorithm in the client request if it is 
     *       an acceptable algorithm by EJBCA.
     *    2. Select the signature algorithm used to sign a certificate revocation list (CRL) issued by the 
     *       certificate issuer providing status information for the certificate specified by CertID.
     *       (NOT APPLIED)
     *    3. Select the signature algorithm used to sign the OCSPRequest if it is an acceptable algorithm in EJBCA.
     *    4. Select a signature algorithm that has been advertised as being the default signature algorithm for 
     *       the signing service using an out-of-band mechanism.
     *    5. Select a mandatory or recommended signature algorithm specified for the version of OCSP in use, aka. 
     *       specified in the properties file.
     * 
     *    The acceptable algorithm by EJBCA are the algorithms specified in ocsp.properties file in 'ocsp.signaturealgorithm'
     * 
     * @param req
     * @param ocspSigningCacheEntry
     * @param signerCert
     * @return
     */
    private String getSigAlg(OCSPReq req, final OcspSigningCacheEntry ocspSigningCacheEntry, final X509Certificate signerCert) {
        String sigAlg = null;
        PublicKey pk = signerCert.getPublicKey();
        // Start with the preferred signature algorithm in the OCSP request
        final Extension preferredSigAlgExtension = req.getExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".8"));
        if (preferredSigAlgExtension != null) {
            final ASN1Sequence preferredSignatureAlgorithms = ASN1Sequence.getInstance(preferredSigAlgExtension.getParsedValue());
            for (int i=0; i<preferredSignatureAlgorithms.size(); i++) {
                final ASN1Encodable asn1Encodable = preferredSignatureAlgorithms.getObjectAt(i);
                final ASN1ObjectIdentifier algorithmOid;
                if (asn1Encodable instanceof ASN1ObjectIdentifier) {
                    // Handle client requests that were adapted to EJBCA 6.1.0's implementation
                    log.info("OCSP request's PreferredSignatureAlgorithms did not contain an PreferredSignatureAlgorithm, but instead an algorithm OID."
                            + " This will not be supported in a future versions of EJBCA.");
                    algorithmOid = (ASN1ObjectIdentifier) asn1Encodable;
                } else {
                    // Handle client requests that provide a proper AlgorithmIdentifier as specified in RFC 6960 + RFC 5280
                    final ASN1Sequence preferredSignatureAlgorithm = ASN1Sequence.getInstance(asn1Encodable);
                    final AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(preferredSignatureAlgorithm.getObjectAt(0));
                    algorithmOid = algorithmIdentifier.getAlgorithm();
                }
                if (algorithmOid != null) {
                    sigAlg = AlgorithmTools.getAlgorithmNameFromOID(algorithmOid);
                    if (sigAlg!=null && OcspConfiguration.isAcceptedSignatureAlgorithm(sigAlg) && AlgorithmTools.isCompatibleSigAlg(pk, sigAlg)) {
                        if (log.isDebugEnabled()) {
                            log.debug("Using OCSP response signature algorithm extracted from OCSP request extension. " + algorithmOid);
                        }
                        return sigAlg;
                    }
                }
            }
        }
        // the signature algorithm used to sign the OCSPRequest
        if(req.getSignatureAlgOID() != null) {
            sigAlg = AlgorithmTools.getAlgorithmNameFromOID(req.getSignatureAlgOID());
            if(OcspConfiguration.isAcceptedSignatureAlgorithm(sigAlg) && AlgorithmTools.isCompatibleSigAlg(pk, sigAlg)) {
                if (log.isDebugEnabled()) {
                    log.debug("OCSP response signature algorithm: the signature algorithm used to sign the OCSPRequest. " + sigAlg);
                }
                return sigAlg;
            }
        }
        // The signature algorithm that has been advertised as being the default signature algorithm for the signing service using an
        // out-of-band mechanism.
        if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
            // If we have an OcspKeyBinding we use this configuration to override the default
            sigAlg = ocspSigningCacheEntry.getOcspKeyBinding().getSignatureAlgorithm();
            if (log.isDebugEnabled()) {
                log.debug("OCSP response signature algorithm: the signature algorithm that has been advertised as being the default signature algorithm " +
                        "for the signing service using an out-of-band mechanism. " + sigAlg);
            }
            return sigAlg;
        }   
        // The signature algorithm specified for the version of OCSP in use.
        String sigAlgs = OcspConfiguration.getSignatureAlgorithm();
        sigAlg = getSigningAlgFromAlgSelection(sigAlgs, pk);
        if (log.isDebugEnabled()) {
            log.debug("Using configured signature algorithm to sign OCSP response. " + sigAlg);
        }
        return sigAlg;
    }

    /**
     * This method takes byte array and translates it onto a OCSPReq class.
     * 
     * @param request the byte array in question.
     * @param remoteAddress The remote address of the HttpRequest associated with this array.
     * @param transactionLogger A transaction logger.
     * @return
     * @throws MalformedRequestException
     * @throws SignRequestException thrown if an unsigned request was processed when system configuration requires that all requests be signed.
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws SignRequestSignatureException
     */
    private OCSPReq translateRequestFromByteArray(byte[] request, String remoteAddress, TransactionLogger transactionLogger)
            throws MalformedRequestException, SignRequestException, SignRequestSignatureException, CertificateException, NoSuchAlgorithmException {
        final OCSPReq ocspRequest;
        try {
            ocspRequest = new OCSPReq(request);
        } catch (IOException e) {
            throw new MalformedRequestException("Could not form OCSP request", e);
        }
        if (ocspRequest.getRequestorName() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Requestor name is null");
            }
        } else {
            if (transactionLogger.isEnabled() || log.isDebugEnabled()) {
                final X500Name requestorDirectoryName = (X500Name) ocspRequest.getRequestorName().getName();
                final String requestor = CertTools.stringToBCDNString(requestorDirectoryName.toString());
                final String requestorRaw = GeneralName.directoryName + ": " + X500Name.getInstance(CeSecoreNameStyle.INSTANCE, requestorDirectoryName).toString();
                if (transactionLogger.isEnabled()) {
                    transactionLogger.paramPut(TransactionLogger.REQ_NAME, requestor);
                    transactionLogger.paramPut(TransactionLogger.REQ_NAME_RAW, requestorRaw);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Requestor name is: '" + requestor + "' Raw: '" + requestorRaw + "'");
                }
            }
        }
        /**
         * check the signature if contained in request. if the request does not contain a signature and the servlet is configured in the way the a
         * signature is required we send back 'sigRequired' response.
         */
        if (log.isDebugEnabled()) {
            log.debug("Incoming OCSP request is signed : " + ocspRequest.isSigned());
        }
        if (ocspRequest.isSigned()) {
            final X509Certificate signercert = checkRequestSignature(remoteAddress, ocspRequest);
            final String signercertIssuerName = CertTools.getIssuerDN(signercert);
            final BigInteger signercertSerNo = CertTools.getSerialNumber(signercert);
            final String signercertSubjectName = CertTools.getSubjectDN(signercert);
            if (transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.SIGN_ISSUER_NAME_DN, signercertIssuerName);
                transactionLogger.paramPut(TransactionLogger.SIGN_SERIAL_NO, signercert.getSerialNumber().toByteArray());
                transactionLogger.paramPut(TransactionLogger.SIGN_SUBJECT_NAME, signercertSubjectName);
                transactionLogger.paramPut(PatternLogger.REPLY_TIME, TransactionLogger.REPLY_TIME);
            }
            // Check if we have configured request verification using the old property file way..
            boolean enforceRequestSigning = OcspConfiguration.getEnforceRequestSigning();
            // Next, check if there is an OcspKeyBinding where signing is required and configured for this request
            // In the case where multiple requests are bundled together they all must be trusting the signer
            for (final Req req : ocspRequest.getRequestList()) {
                OcspSigningCacheEntry ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(req.getCertID());
                if (ocspSigningCacheEntry==null) {
                    if (log.isTraceEnabled()) {
                        log.trace("Using default responder to check signature.");
                    }
                    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
                }   
                if (ocspSigningCacheEntry!=null && ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                    if (log.isTraceEnabled()) {
                        log.trace("ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate: " + ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate());
                    }
                    final OcspKeyBinding ocspKeyBinding = ocspSigningCacheEntry.getOcspKeyBinding();
                    if (log.isTraceEnabled()) {
                        log.trace("OcspKeyBinding " + ocspKeyBinding.getId() + ", RequireTrustedSignature: " + ocspKeyBinding.getRequireTrustedSignature());
                    }
                    if (ocspKeyBinding.getRequireTrustedSignature()) {
                        enforceRequestSigning = true;
                        boolean isTrusted = false;
                        final List<InternalKeyBindingTrustEntry> trustedCertificateReferences = ocspKeyBinding.getTrustedCertificateReferences();
                        if (trustedCertificateReferences.isEmpty()) {
                            // We trust ANY cert from a known CA
                            isTrusted = true;
                        } else {
                            for (final InternalKeyBindingTrustEntry trustEntry : trustedCertificateReferences) {
                                final int trustedCaId = trustEntry.getCaId();
                                final BigInteger trustedSerialNumber = trustEntry.fetchCertificateSerialNumber();
                                if (log.isTraceEnabled()) {
                                    log.trace("Processing trustedCaId="+trustedCaId + " trustedSerialNumber="+trustedSerialNumber + " signercertIssuerName.hashCode()="+
                                            signercertIssuerName.hashCode()+" signercertSerNo="+signercertSerNo);
                                }
                                if (trustedCaId == signercertIssuerName.hashCode()) {
                                    if (trustedSerialNumber == null) {
                                        // We trust any certificate from this CA
                                        isTrusted = true;
                                        if (log.isTraceEnabled()) {
                                            log.trace("Trusting request signature since ANY certificate from issuer "+trustedCaId+" is trusted.");
                                        }
                                        break;
                                    } else if (signercertSerNo.equals(trustedSerialNumber)) {
                                        // We trust this particular certificate from this CA
                                        isTrusted = true;
                                        if (log.isTraceEnabled()) {
                                            log.trace("Trusting request signature since certificate with serialnumber " + trustedSerialNumber + " from issuer "+trustedCaId+" is trusted.");
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        if (!isTrusted) {
                            final String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.notallowed", signercertSubjectName, signercertIssuerName,
                                    signercertSerNo.toString(16));
                            log.info(infoMsg);
                            throw new SignRequestSignatureException(infoMsg);
                        }
                    }
                }
            }
            if (enforceRequestSigning) {
                // If it verifies OK, check if it is revoked
                final String cacheLookupKey = OcspRequestSignerStatusCache.INSTANCE.createCacheLookupKey(signercertIssuerName, signercertSerNo);
                CertificateStatus status = OcspRequestSignerStatusCache.INSTANCE.getCachedCertificateStatus(cacheLookupKey);
                if (status==null) {
                    status = certificateStoreSession.getStatus(signercertIssuerName, signercertSerNo);
                    OcspRequestSignerStatusCache.INSTANCE.updateCachedCertificateStatus(cacheLookupKey, status);
                }
                /*
                 * CertificateStatus.NOT_AVAILABLE means that the certificate does not exist in database. We treat this as ok, because it may be so that only revoked
                 * certificates is in the (external) OCSP database.
                 */
                if (status.equals(CertificateStatus.REVOKED)) {
                    String serno = signercertSerNo.toString(16);
                    String infoMsg = intres.getLocalizedMessage("ocsp.infosigner.revoked", signercertSubjectName, signercertIssuerName, serno);
                    log.info(infoMsg);
                    throw new SignRequestSignatureException(infoMsg);
                }
            }
        } else {
            if (OcspConfiguration.getEnforceRequestSigning()) {
                // Signature required
                throw new SignRequestException("Signature required");
            }
            // Next, check if there is an OcspKeyBinding where signing is required and configured for this request
            // In the case where multiple requests are bundled together they all must be trusting the signer
            for (final Req req : ocspRequest.getRequestList()) {
                OcspSigningCacheEntry ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(req.getCertID());
                if (ocspSigningCacheEntry==null) {
                    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
                }
                if (ocspSigningCacheEntry != null && ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                    final OcspKeyBinding ocspKeyBinding = ocspSigningCacheEntry.getOcspKeyBinding();
                    if (ocspKeyBinding.getRequireTrustedSignature()) {
                        throw new SignRequestException("Signature required");
                    }
                }
            }
        }
        return ocspRequest;
    }

    /**
     * Checks the signature on an OCSP request. Does not check for revocation of the signer certificate
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
        // Get all certificates embedded in the request (probably a certificate chain)
        try {
            final X509CertificateHolder[] certs = req.getCerts();
            String signerSubjectDn = null;
            // We must find a certificate to verify the signature with...
            boolean verifyOK = false;
            for (X509CertificateHolder cert : certs) {
                final X509Certificate certificate = certificateConverter.getCertificate(cert);
                try {
                    if (req.isSignatureValid(CertTools.genContentVerifierProvider(certificate.getPublicKey()))) {
                        signercert = certificate; // if the request signature verifies by this certificate, this is the signer cert 
                        signerSubjectDn = CertTools.getSubjectDN(signercert);
                        log.info(intres.getLocalizedMessage("ocsp.infosigner", signerSubjectDn));
                        verifyOK = true;
                        // Check that the signer certificate can be verified by one of the CA-certificates that we answer for
                        final X509Certificate signerca = CaCertificateCache.INSTANCE.findLatestBySubjectDN(HashID.getFromIssuerDN(signercert));
                        if (signerca != null) {
                            try {
                                signercert.verify(signerca.getPublicKey());
                                final Date now = new Date();
                                if (log.isDebugEnabled()) {
                                    log.debug("Checking validity. Now: " + now + ", signerNotAfter: " + signercert.getNotAfter());
                                }
                                try {
                                    // Check validity of the request signing certificate
                                    CertTools.checkValidity(signercert, now);
                                } catch (CertificateNotYetValidException e) {
                                    log.info(intres.getLocalizedMessage("ocsp.infosigner.certnotyetvalid", signerSubjectDn, CertTools.getIssuerDN(signercert), e.getMessage()));
                                    verifyOK = false;
                                } catch (CertificateExpiredException e) {
                                    log.info(intres.getLocalizedMessage("ocsp.infosigner.certexpired", signerSubjectDn, CertTools.getIssuerDN(signercert), e.getMessage()));
                                    verifyOK = false;
                                }
                                try {
                                    // Check validity of the CA certificate
                                    CertTools.checkValidity(signerca, now);
                                } catch (CertificateNotYetValidException e) {
                                    log.info(intres.getLocalizedMessage("ocsp.infosigner.certnotyetvalid", CertTools.getSubjectDN(signerca), CertTools.getIssuerDN(signerca), e.getMessage()));
                                    verifyOK = false;
                                } catch (CertificateExpiredException e) {
                                    log.info(intres.getLocalizedMessage("ocsp.infosigner.certexpired", CertTools.getSubjectDN(signerca), CertTools.getIssuerDN(signerca), e.getMessage()));
                                    verifyOK = false;
                                }
                            } catch (SignatureException | InvalidKeyException e) {
                                log.info(intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", signerSubjectDn, CertTools.getIssuerDN(signercert), e.getMessage()));
                                verifyOK = false;
                            }
                        } else {
                            log.info(intres.getLocalizedMessage("ocsp.infosigner.nocacert", signerSubjectDn, CertTools.getIssuerDN(signercert)));
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
                if (signerSubjectDn == null && certs.length > 0) {
                    signerSubjectDn = CertTools.getSubjectDN(certificateConverter.getCertificate(certs[0]));
                }
                String errMsg = intres.getLocalizedMessage("ocsp.errorinvalidsignature", signerSubjectDn);
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
    
    private void assertAcceptableResponseExtension(OCSPReq req) throws OcspFailureException {
        if (null == req) {
            throw new IllegalArgumentException();
        }
        if (req.hasExtensions()) {
            final Extension acceptableResponsesExtension = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_response);
            if (acceptableResponsesExtension != null) {
                // RFC 6960 4.4.3 AcceptableResponses ::= SEQUENCE OF OBJECT IDENTIFIER
                final ASN1Sequence sequence = ASN1Sequence.getInstance(acceptableResponsesExtension.getExtnValue().getOctets());
                @SuppressWarnings("unchecked")
                final Enumeration<ASN1ObjectIdentifier> oids = sequence.getObjects();
                boolean supportsResponseType = false;
                while (oids.hasMoreElements()) {
                    final ASN1ObjectIdentifier oid = oids.nextElement();
                    if (oid.equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                        // This is the response type we support, so we are happy! Break the loop.
                        supportsResponseType = true;
                        if (log.isDebugEnabled()) {
                            log.debug("Response type supported: " + oid.getId());
                        }
                        break;
                    }
                }
                if (!supportsResponseType) {
                    final String msg = "Required response type not supported, this responder only supports id-pkix-ocsp-basic.";
                    log.info("OCSP Request type not supported: " + msg);
                    throw new OcspFailureException(msg);
                }
            }
        }
    }

    /**
     * When a timer expires, this method will update
     * 
     * According to JSR 220 FR (18.2.2), this method may not throw any exceptions.
     * 
     * @param timer The timer whose expiration caused this notification.
     * 
     */
    @Timeout
    /* Glassfish 2.1.1:
     * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
     * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
     */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">timeoutHandler: " + timer.getInfo().toString());
        }
        // reloadTokenAndChainCache cancels old timers and adds a new timer
        reloadOcspSigningCache();
        if (log.isTraceEnabled()) {
            log.trace("<timeoutHandler");
        }
    }

    /**
     * This method cancels all timers associated with this bean.
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private void cancelTimers(final int id) {
        if (log.isTraceEnabled()) {
            log.trace(">cancelTimers");
        }
        final Collection<Timer> timers = timerService.getTimers();
        for (final Timer timer : timers) {
            final int currentTimerId = (Integer) timer.getInfo();
            if (currentTimerId==id) {
                timer.cancel();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<cancelTimers, timers canceled: " + timers.size());
        }
    }

    private int getTimerCount(final int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getTimerCount");
        }
        int count = 0;
        final Collection<Timer> timers = timerService.getTimers();
        for (final Timer timer : timers) {
            final int currentTimerId = (Integer) timer.getInfo();
            if (currentTimerId==id) {
                count++;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getTimerCount, timers: " + count);
        }
        return count;
    }

    /**
     * Adds a timer to the bean
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private Timer addTimer(long interval, Integer id) {
        if (log.isTraceEnabled()) {
            log.trace(">addTimer: " + id + ", interval: " + interval);
        }
        Timer ret = null;
        if (interval > 0) {
        	// Create non-persistent timer that fires once
            ret = timerService.createSingleActionTimer(interval, new TimerConfig(id, false));
            if (log.isTraceEnabled()) {
                log.trace("<addTimer: " + id + ", interval: " + interval + ", " + ret.getNextTimeout().toString());
            }
        }
        return ret;
    }

    /** 
     * 
     * @param req OCSP request to check
     * @return true if the request does not have any extensions preventing a pre-signed response to be served, false if a pre-signed response should not be served
     */
    private boolean reqHasExtensionsOkToStoreResponse(final OCSPReq req, final OcspSigningCacheEntry ocspSigningCacheEntry) {
        if (!req.hasExtensions()) {
            // return fast if there are no request extensions at all, then we can serve a pre-signed response
            return true;
        }
        // Nonce is also ok to include in the request, because the server can ignore the nonce and send pre-signed response without nonce
        // it's configured in the OCSP key binding (or globally) if the response should contain nonce
        if (ocspSigningCacheEntry != null && req.getExtensionOIDs().size() == 1 && req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) != null) {
            final boolean nonceEnable = (ocspSigningCacheEntry.getOcspKeyBinding() != null ? ocspSigningCacheEntry.getOcspKeyBinding().isNonceEnabled() :
                ((GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID)).getNonceEnabled());
            if (!nonceEnable) {
                // Only say it's ok if the response will not contain nonce
                return true;
            }
        } else if (ocspSigningCacheEntry == null) {
            // If CA expired ocspSigningCacheEntry is null
            // pre-production is then ok as this enables sending "final responses" as response for expired CAs as specified in ETSI EN 319 411-2
            if (log.isDebugEnabled()) {
                log.debug("ocspSigningCacheEntry is null, it may be an expired CA, allowing to use pre-produced responses to issue a 'final' response (ETSI EN 319 411-2)");
            }
            return true;
        }

        // Not ok to cache the response, it may contains extensions preventing it to be served to other clients
        if (log.isDebugEnabled()) {
            log.debug("Not able to store pre-produced OCSP response because there are extensions (other than Nonce): " + req.getExtensionOIDs().size());
        }
        return false;
    }
    
    @Override
    public OcspResponseInformation getOcspResponse(final byte[] request, final X509Certificate[] requestCertificates, String remoteAddress,
            String xForwardedFor, StringBuffer requestUrl, final AuditLogger auditLogger, final TransactionLogger transactionLogger, boolean isPreSigning, 
            boolean issueFinalResponse)
            throws MalformedRequestException, OCSPException {
        //Check parameters
        if (auditLogger == null) {
            throw new InvalidParameterException("Illegal to pass a null audit logger to OcspResponseSession.getOcspResponse");
        }
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
        if (!isPreSigning && transactionLogger.isEnabled()) {
            transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
        }
        if (!isPreSigning  && auditLogger.isEnabled()) {
            auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            auditLogger.paramPut(AuditLogger.OCSPREQUEST, StringTools.hex(request));
        }
        OCSPReq req;
        long maxAge = OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
        OCSPRespBuilder responseGenerator = new OCSPRespBuilder();
        X509Certificate signerCert = null;
        String serialNrForResponseStore = null;
        int caIdForResponseStore = 0;
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
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.NUM_CERT_ID, ocspRequests.length);
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
            }
            OcspSigningCacheEntry ocspSigningCacheEntry = null;
            long nextUpdate = OcspConfiguration.getUntilNextUpdate(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);
            Map<ASN1ObjectIdentifier, Extension> responseExtensions = new HashMap<>();
            
            // Look over the status requests
            List<OCSPResponseItem> responseList = new ArrayList<>();
            // If the Extended Revoked Definition should be added for certificates that we can not find in the database, see RFC6960 4.4.8
            boolean addExtendedRevokedExtension = false;
            Date producedAt = null;
            
            for (Req ocspRequest : ocspRequests) {
                CertificateID certId = ocspRequest.getCertID();
                ASN1ObjectIdentifier certIdhash = certId.getHashAlgOID();
                
                if (!OIWObjectIdentifiers.idSHA1.equals(certIdhash) && !NISTObjectIdentifiers.id_sha256.equals(certIdhash)) {
                    throw new InvalidAlgorithmException("CertID with SHA1 and SHA256 are supported, not: "+certIdhash.getId());
                }
                if (!isPreSigning && transactionLogger.isEnabled()) {
                    transactionLogger.paramPut(TransactionLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
                    transactionLogger.paramPut(TransactionLogger.DIGEST_ALGOR, certId.getHashAlgOID().toString());
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
                    transactionLogger.paramPut(TransactionLogger.ISSUER_KEY, certId.getIssuerKeyHash());
                }
                if (!isPreSigning && auditLogger.isEnabled()) {
                    auditLogger.paramPut(AuditLogger.ISSUER_KEY, certId.getIssuerKeyHash());
                    auditLogger.paramPut(AuditLogger.SERIAL_NOHEX, certId.getSerialNumber().toByteArray());
                    auditLogger.paramPut(AuditLogger.ISSUER_NAME_HASH, certId.getIssuerNameHash());
                }
                final String hash = StringTools.hex(certId.getIssuerNameHash());
                if (xForwardedFor==null && !isPreSigning) {
                    log.info(intres.getLocalizedMessage("ocsp.inforeceivedrequest", certId.getSerialNumber().toString(16), hash, remoteAddress));
                } else if (!isPreSigning){
                    log.info(intres.getLocalizedMessage("ocsp.inforeceivedrequestwxff", certId.getSerialNumber().toString(16), hash, remoteAddress, xForwardedFor));
                }
                
                ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(certId);
                OcspDataConfigCacheEntry ocspDataConfig = OcspDataConfigCache.INSTANCE.getEntry(certId);
                // Locate the CA which gave out the certificate
                if (Objects.isNull(ocspSigningCacheEntry)) {

                    GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                            .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);

                    // An extra cache reload in case we are on an MS compatible CA
                    if (Objects.isNull(ocspDataConfig) && OcspDataConfigCache.INSTANCE.getCaModeCompatiblePresent() ||
                            !Objects.isNull(ocspDataConfig) && ocspDataConfig.isMsCaCompatible()) {
                        reloadOcspSigningCache();
                    }
                    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(certId);
                    ocspDataConfig = OcspDataConfigCache.INSTANCE.getEntry(certId);

                    if (Objects.isNull(ocspSigningCacheEntry) && ocspConfiguration.getOcspSigningCacheUpdateEnabled()) {
                        // Now try to update the cache from internal key bindings

                        //Could it be that we haven't updated the OCSP Signing Cache?
                        if (ocspDataConfig != null && ocspDataConfig.isMsCaCompatible()) {
                            ocspSigningCacheEntry = findAndAddMissingCacheEntry(certId, true);
                        } else {
                            ocspSigningCacheEntry = findAndAddMissingCacheEntry(certId, false);
                        }

                    }
                }
                                
                // We only store pre-produced single responses
                if (ocspRequests.length == 1 && ocspDataConfig != null && ocspDataConfig.isPreProductionEnabled()) {
                    
                    final OcspResponseData ocspResponseData = ocspDataSession.findOcspDataByCaIdSerialNumber(ocspDataConfig.getCaId(), certId.getSerialNumber().toString());

                    // 1. If no stored response exists. Skip this, produce and new one and store it later on (if storing on-demand is enabled)
                    // 2. If a response is stored, still valid and request has only supported extensions: return it.
                    // 3. If a response is stored and nextUpdate is null: Ignore it and produce new response.
                    if (!isPreSigning && ocspResponseData != null && ocspResponseData.getNextUpdate() != null
                            && ocspResponseData.getNextUpdate() > System.currentTimeMillis()
                            && reqHasExtensionsOkToStoreResponse(req, ocspSigningCacheEntry)) {
                        OCSPResp ocspResp = null;
                        try {
                            ocspResp = new OCSPResp(ocspResponseData.getOcspResponse());
                            if (ocspSigningCacheEntry != null && ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                                maxAge = ocspSigningCacheEntry.getOcspKeyBinding().getMaxAge() * 1000L;
                            }
                            if (log.isDebugEnabled()) {
                                log.debug("Returning pre-produced OCSP response for CA " + ocspResponseData.getCaId() + " and cert serial "
                                        + ocspResponseData.getSerialNumber());
                            }

                            // Audit ant transaction log before returning the response info (if not a pre-signing situation).
                            if (auditLogger.isEnabled()) {
                                auditLogger.paramPut(AuditLogger.OCSPRESPONSE, StringTools.hex(ocspResponseData.getOcspResponse()));
                                auditLogger.writeln();
                                auditLogger.flush();
                            }

                            if (transactionLogger.isEnabled()) {
                                if (ocspSigningCacheEntry != null) {
                                    transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN,
                                            ocspSigningCacheEntry.getSigningCertificateIssuerDn());
                                    transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN_RAW,
                                            ocspSigningCacheEntry.getSigningCertificateIssuerDnRaw());
                                    // Issuer of the requested certificate is not logged to save database lookup
                                }
                                org.bouncycastle.cert.ocsp.CertificateStatus status = ((BasicOCSPResp) ocspResp.getResponseObject()).getResponses()[0]
                                        .getCertStatus();

                                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, fetchCertStatus(status));

                                if (!Objects.isNull(status) && ((RevokedStatus) status).hasRevocationReason()) {
                                    transactionLogger.paramPut(TransactionLogger.REV_REASON, ((RevokedStatus) status).getRevocationReason());
                                }
                                transactionLogger.writeln();
                                transactionLogger.flush();
                            }
                            return new OcspResponseInformation(ocspResp, maxAge, signerCert);
                        } catch (IOException e) {
                            log.warn("Pre-produced OCSP response for certificate with serialNr '" + certId.getSerialNumber()
                                    + "' was malformed. Producing new response.");
                        }
                    }
                    // All prerequisites for pre-production are OK. However, no valid response is persisted. Setting the serialNrForResponseStore will
                    // result in the produced one to be stored. Don't store responses without nextUpdate set.
                    if ((ocspDataConfig.isStoreResponseOnDemand() || isPreSigning) && reqHasExtensionsOkToStoreResponse(req, ocspSigningCacheEntry)) {
                        TimeZone tz = TimeZone.getTimeZone("GMT");
                        Calendar finalResponseTime = Calendar.getInstance(tz);
                        finalResponseTime.clear();
                        finalResponseTime.set(9999, 11, 31, 23, 59, 59); 
                        // 99991231235959Z "final response" must not be overwritten.
                        if (ocspResponseData == null || 
                            ocspResponseData.getNextUpdate() != finalResponseTime.getTimeInMillis()) {
                            serialNrForResponseStore = certId.getSerialNumber().toString();
                            caIdForResponseStore = ocspDataConfig.getCaId();
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug("Not storing OCSP response for certificate with serialNr '" + certId.getSerialNumber() + 
                                        "', a final response has already been issued.");
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        if (ocspDataConfig != null) {
                            log.debug("Pre-production of OCSP responses is not enabled (" + ocspDataConfig.isPreProductionEnabled() + ") for CA " + ocspDataConfig.getCaId());
                        } else {
                            log.debug("Pre-production of OCSP responses is not enabled because ocspDataConfig is null");
                        }
                    }
                }
                
                if (ocspSigningCacheEntry != null) {
                    if (!isPreSigning && transactionLogger.isEnabled()) {
                        // This will be the issuer DN of the signing certificate, whether an OCSP responder or an internal CA  
                        transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN,
                                ocspSigningCacheEntry.getSigningCertificateIssuerDn());
                        transactionLogger.paramPut(TransactionLogger.OCSP_CERT_ISSUER_NAME_DN_RAW,
                                ocspSigningCacheEntry.getSigningCertificateIssuerDnRaw());
                    }
                } else {
                    /*
                     * if the certId was issued by an unknown CA 
                     * 
                     * The algorithm here: 
                     * We will sign the response with the CA that issued the last certificate(certId) in the request. If the issuing CA is not available on 
                     * this server, we sign the response with the default responderId (from params in web.xml). We have to look up the ca-certificate for 
                     * each certId in the request though, as we will check for revocation on the ca-cert as well when checking for revocation on the certId.
                     */                
                    // We could not find certificate for this request so get certificate for default responder
                    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getDefaultEntry();
                    if (ocspSigningCacheEntry != null) {
                        // We could not find the CA
                        final OcspKeyBinding defaultKeyBind = OcspSigningCache.INSTANCE.getDefaultEntry().getOcspKeyBinding();
                        // If not overridden in the default key binding, answer UnknowStatus
                        org.bouncycastle.cert.ocsp.CertificateStatus status = new UnknownStatus();
                        String statusName = "UnknownStatus";
                        int statusLogCode = OCSPResponseItem.OCSP_UNKNOWN;
                        if (defaultKeyBind != null) {
                            if (defaultKeyBind.getNonExistingRevoked()) {
                                // See NonExistingRevoked handling below for an explanation.
                                // We return certificateHold just to be safe, in case the CA certificate is not yet available for some reason.
                                status = new RevokedStatus(new RevokedInfo(new ASN1GeneralizedTime(new Date(0)),
                                        CRLReason.lookup(CRLReason.certificateHold)));
                                statusName = "RevokedStatus";
                                statusLogCode = OCSPResponseItem.OCSP_REVOKED;
                            } else if (defaultKeyBind.getNonExistingUnauthorized()) {
                                // In order to save on cycles and mitigate the chances of a DOS attack, we'll return a unsigned unauthorized reply. 
                                ocspResponse = responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
                                if (!isPreSigning && auditLogger.isEnabled()) {
                                    auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                                }
                                if (!isPreSigning && transactionLogger.isEnabled()) {
                                    transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                                }
                                log.info(intres.getLocalizedMessage("ocsp.errorfindcacertusedefault", StringTools.hex(certId.getIssuerNameHash()), "Unauthorized"));
                                // Return early here
                                return new OcspResponseInformation(ocspResponse, maxAge, null);
                            }
                        }
                        responseList.add(new OCSPResponseItem(certId, status, nextUpdate));
                        String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacertusedefault", StringTools.hex(certId.getIssuerNameHash()), statusName);
                        log.info(errMsg);
                        if (!isPreSigning && transactionLogger.isEnabled()) {
                            transactionLogger.paramPut(TransactionLogger.CERT_STATUS, statusLogCode);
                        }
                        continue;
                    } else {
                        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
                        String defaultResponder = ocspConfiguration.getOcspDefaultResponderReference();
                        String errMsg = intres.getLocalizedMessage("ocsp.errorfindcacert", StringTools.hex(certId.getIssuerNameHash()),
                                defaultResponder);
                        log.error(errMsg);
                        // If we are responding to multiple requests, the last found ocspSigningCacheEntry will be used in the end
                        // so even if there are not any one now, it might be later when it is time to sign the responses.
                        // Since we only will sign the entire response once if there is at least one valid ocspSigningCacheEntry
                        // we might as well include the unknown requests.
                        responseList.add(new OCSPResponseItem(certId, new UnknownStatus(), nextUpdate));
                        continue;
                    }
                }
                
                final org.bouncycastle.cert.ocsp.CertificateStatus certStatus;
                // Check if the cacert (or the default responderid) is revoked
                X509Certificate caCertificate = ocspSigningCacheEntry.getIssuerCaCertificate();
                final CertificateStatus signerIssuerCertStatus = ocspSigningCacheEntry.getIssuerCaCertificateStatus();
                final String caCertificateSubjectDn = CertTools.getSubjectDN(caCertificate);
                String signedBehalfOfCaSubjectDn = null;
                CertificateStatus onBehalfOfCaStatus = CertificateStatus.OK; // placeholder
                CertificateStatusHolder certificateStatusHolder = null;
                OCSPResponseItem respItem;
                
                X509Certificate shouldSignOnBehalfCaCert = null;
                
                // only necessary if sign on behalf entries are present for corresponding cache entry
                if(!ocspSigningCacheEntry.getSignedBehalfOfCaIds().isEmpty()) {
                    List<CertificateDataWrapper> certificateWrappers = 
                            certificateStoreSession.getCertificateDataBySerno(certId.getSerialNumber());
                    
                    for(CertificateDataWrapper certificateWrapper: certificateWrappers) {
                        if(certificateWrapper.getCertificateData()==null || certificateWrapper.getCertificate()==null) {
                            continue;
                        }
                        if(certificateWrapper.getCertificateData().getIssuerDN().equals(caCertificateSubjectDn)) {
                            break;
                        } else {
                            Certificate fetchedCertificate = certificateWrapper.getCertificate();
                            if(!(fetchedCertificate instanceof X509Certificate)) {
                                continue;
                            }
                            CertificateID issuerCertId = ocspSigningCacheEntry.getSignBehalfOfCaCertId(
                                                            (X509Certificate) fetchedCertificate);
    
                            if(issuerCertId!=null) {
                                shouldSignOnBehalfCaCert = ocspSigningCacheEntry.getSignBehalfOfCaCertificate(issuerCertId);
                                signedBehalfOfCaSubjectDn = CertTools.getSubjectDN(shouldSignOnBehalfCaCert);
                                onBehalfOfCaStatus = ocspSigningCacheEntry.getSignedBehalfOfCaStatus().get(issuerCertId);
                                log.debug("ocsp will be signed behalf of: \"" + signedBehalfOfCaSubjectDn 
                                                    + "\" by:\"" + caCertificateSubjectDn + "\"");
                                break;
                            }
                        }
                    }
                }
                
                if(shouldSignOnBehalfCaCert!=null) {
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN,
                            CertTools.getIssuerDN(shouldSignOnBehalfCaCert));
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN_RAW,
                            shouldSignOnBehalfCaCert.getIssuerDN().getName());
                } else {
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN,
                            ocspSigningCacheEntry.getSigningCertificateIssuerDn());
                    transactionLogger.paramPut(TransactionLogger.ISSUER_NAME_DN_RAW,
                            ocspSigningCacheEntry.getSigningCertificateIssuerDnRaw());
                }

                final List<String> extensionOids = ocspSigningCacheEntry.getOcspKeyBinding() != null
                        ? ocspSigningCacheEntry.getOcspKeyBinding().getOcspExtensions()
                        : new ArrayList<>();
                
                // Intended for debugging. Will usually be null
                String alwaysUseOid = OcspConfiguration.getAlwaysSendCustomOCSPExtension();
                if (alwaysUseOid != null && !extensionOids.contains(alwaysUseOid)) {
                    extensionOids.add(alwaysUseOid);
                }
                                
                if (signerIssuerCertStatus.equals(CertificateStatus.REVOKED)) {
                    /*
                     * According to chapter 2.7 in RFC2560:
                     * 
                     * 2.7 CA Key Compromise If an OCSP responder knows that a particular CA's private key has been compromised, it MAY return the revoked
                     * state for all certificates issued by that CA.
                     */
                    // If we've ended up here it's because the signer issuer certificate was revoked.                    
                    certStatus = new RevokedStatus(new RevokedInfo(new ASN1GeneralizedTime(signerIssuerCertStatus.revocationDate),
                            CRLReason.lookup(signerIssuerCertStatus.revocationReason)));
                    log.info(intres.getLocalizedMessage("ocsp.signcertissuerrevoked", CertTools.getSerialNumberAsString(caCertificate),
                            CertTools.getSubjectDN(caCertificate)));
                    respItem = new OCSPResponseItem(certId, certStatus, nextUpdate);
                    if (!isPreSigning && transactionLogger.isEnabled()) {
                        transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_REVOKED);
                        transactionLogger.paramPut(TransactionLogger.REV_REASON, signerIssuerCertStatus.revocationReason);
                    }
                } else if(!onBehalfOfCaStatus.equals(CertificateStatus.OK)) {
                    certStatus = new UnknownStatus();
                    // allow persist responses with 'unknown' if issuer CA is revoked
                    log.info(intres.getLocalizedMessage("ocsp.issuerrevoked", CertTools.getSerialNumberAsString(shouldSignOnBehalfCaCert),
                            CertTools.getSubjectDN(shouldSignOnBehalfCaCert)));
                    respItem = new OCSPResponseItem(certId, certStatus, nextUpdate);
                    if (!isPreSigning && transactionLogger.isEnabled()) {
                        transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_UNKNOWN);
                        if(onBehalfOfCaStatus.equals(CertificateStatus.REVOKED)) {
                            transactionLogger.paramPut(TransactionLogger.REV_REASON, onBehalfOfCaStatus.revocationReason);
                        } else {
                            transactionLogger.paramPut(TransactionLogger.REV_REASON, CRLReason.certificateHold);
                        }
                    }
                } else {
                    /**
                     * Here is the actual check for the status of the sought certificate (easy to miss). Here we grab just the status if there aren't
                     * any OIDs defined (default case), but if there are we'll probably need the certificate as well. If that's the case, we'll grab
                     * the certificate in the same transaction.
                     */
                    CertificateStatus status;
                    String issuerDnOcspRequest = caCertificateSubjectDn;
                    if(signedBehalfOfCaSubjectDn!=null) {
                        issuerDnOcspRequest = signedBehalfOfCaSubjectDn;
                        // we will also use certificate profile settings for issuing certificate
                    }
                    if (extensionOids.isEmpty()) {
                        status = certificateStoreSession.getStatus(issuerDnOcspRequest, certId.getSerialNumber());
                    } else {
                        certificateStatusHolder = certificateStoreSession.getCertificateAndStatus(issuerDnOcspRequest, certId.getSerialNumber());
                        status = certificateStatusHolder.getCertificateStatus();
                    }
                    if (!isPreSigning && transactionLogger.isEnabled()) {
                        transactionLogger.paramPut(TransactionLogger.CERT_PROFILE_ID, String.valueOf(status.certificateProfileId));
                    }
                    // If we have an OcspKeyBinding configured for this request, we override the default value
                    if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                        nextUpdate = ocspSigningCacheEntry.getOcspKeyBinding().getUntilNextUpdate()*1000L;
                    }
                    // If we have an explicit value configured for this certificate profile, we override the the current value with this value
                    if (status.certificateProfileId != CertificateProfileConstants.CERTPROFILE_NO_PROFILE &&
                            OcspConfiguration.isUntilNextUpdateConfigured(status.certificateProfileId)) {
                        nextUpdate = OcspConfiguration.getUntilNextUpdate(status.certificateProfileId);
                    }
                    // If we have an OcspKeyBinding configured for this request, we override the default value
                    if (ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                        maxAge = ocspSigningCacheEntry.getOcspKeyBinding().getMaxAge()*1000L;
                    }
                    // If we have an explicit value configured for this certificate profile, we override the the current value with this value
                    if (status.certificateProfileId != CertificateProfileConstants.CERTPROFILE_NO_PROFILE &&
                            OcspConfiguration.isMaxAgeConfigured(status.certificateProfileId)) {
                        maxAge = OcspConfiguration.getMaxAge(status.certificateProfileId);
                    }

                    final String sStatus;
                    if (status.equals(CertificateStatus.NOT_AVAILABLE)) {
                        // No revocation info available for this cert, handle it
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to find revocation information for certificate with serial '" + certId.getSerialNumber().toString(16)
                                    + "'" + " from issuer '" + issuerDnOcspRequest + "'");
                        }
                        /* 
                         * If we do not treat non existing certificates as good or revoked
                         * OR
                         * we don't actually handle requests for the CA issuing the certificate asked about
                         * then we return unknown 
                         * */
                        if (OcspConfigurationCache.INSTANCE.isNonExistingGood(requestUrl, ocspSigningCacheEntry.getOcspKeyBinding()) &&
                                OcspSigningCache.INSTANCE.getEntry(certId) != null) {
                            sStatus = "good";
                            certStatus = null; // null means "good" in OCSP
                            if (!isPreSigning && transactionLogger.isEnabled()) {
                                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_GOOD);
                                transactionLogger.paramPut(TransactionLogger.REV_REASON, CRLReason.certificateHold);
                            }
                        } else if (OcspConfigurationCache.INSTANCE.isNonExistingRevoked(requestUrl, ocspSigningCacheEntry.getOcspKeyBinding()) &&
                                OcspSigningCache.INSTANCE.getEntry(certId) != null) {
                            sStatus = "revoked";
                            // When answering revoked for unknown (non issued) certificates RFC6960 section 2.2 specifies:
                            // When a responder sends a "revoked" response to a status request for a non-issued certificate, the responder MUST include the extended
                            // revoked definition response extension (Section 4.4.8) in the response, indicating that the OCSP responder supports the extended
                            // definition of the "revoked" state to also cover non-issued certificates.  In addition, the SingleResponse related to this
                            // non-issued certificate:
                            // - MUST specify the revocation reason certificateHold (6),
                            // - MUST specify the revocationTime January 1, 1970, and
                            // - MUST NOT include a CRL references extension (Section 4.4.2) or any CRL entry extensions (Section 4.4.5).
                            certStatus = new RevokedStatus(new RevokedInfo(new ASN1GeneralizedTime(new Date(0)),
                                    CRLReason.lookup(CRLReason.certificateHold)));
                            if (!isPreSigning && transactionLogger.isEnabled()) {
                                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_REVOKED); 
                                transactionLogger.paramPut(TransactionLogger.REV_REASON, CRLReason.certificateHold);
                            }
                            // Unknown certificate, "non issued", add the Extended Revoked Definition, RFC6960 4.4.8
                            addExtendedRevokedExtension = true;
                        } else if (OcspConfigurationCache.INSTANCE.isNonExistingUnauthorized(ocspSigningCacheEntry.getOcspKeyBinding())
                                && OcspSigningCache.INSTANCE.getEntry(certId) != null) {
                            // In order to save on cycles and mitigate the chances of a DOS attack, we'll return a unsigned unauthorized reply. 
                            ocspResponse = responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
                            if (!isPreSigning && auditLogger.isEnabled()) {
                                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                            }
                            if (!isPreSigning && transactionLogger.isEnabled()) {
                                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                            }
                            log.info(intres.getLocalizedMessage("ocsp.errorfindcert", certId.getSerialNumber().toString(16), caCertificateSubjectDn));
                            //Return early here
                            return new OcspResponseInformation(ocspResponse, maxAge, null);
                        } else {
                            sStatus = "unknown";
                            certStatus = new UnknownStatus();
                            if (!isPreSigning && transactionLogger.isEnabled()) {
                                transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_UNKNOWN);
                                transactionLogger.paramPut(TransactionLogger.REV_REASON, CRLReason.certificateHold);
                            }
                            // Dont persist responses with 'unknown'
                            serialNrForResponseStore = null;
                            caIdForResponseStore = 0;
                        }
                    } else if (status.equals(CertificateStatus.REVOKED)) {
                        // Revocation info available for this cert, handle it
                        sStatus = "revoked";
                        int reasonCode = status.revocationReason;
                        if (reasonCode < 0) {
                            log.info("Revoked certificate with serial number " + certId.getSerialNumber().toString(16) + " has revocation reason -1 (not revoked), using revocation reason 0 (unspecified) instead.");
                            reasonCode = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
                        }
                        // CA/B Forum Baseline Requirements 1.7.1+ require that reason code is omitted when it is Unspecified.
                        // See section 7.3 and 7.2.2 in https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.7.1.pdf
                        // Since EJBCA 7.9 this is optional, enabled by default per key binding. See ECA-10571 for more info.
                        final CRLReason crlReason;
                        final OcspKeyBinding currentKBEntry = ocspSigningCacheEntry.getOcspKeyBinding();
                        
                        if (currentKBEntry != null && currentKBEntry.isOmitReasonCodeEnabled() && reasonCode == RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED) {
                            crlReason = null;
                        } else {
                            crlReason = CRLReason.lookup(reasonCode);
                        }
                        certStatus = new RevokedStatus(new RevokedInfo(new ASN1GeneralizedTime(status.revocationDate), crlReason));

                        if (!isPreSigning && transactionLogger.isEnabled()) {
                            transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_REVOKED);
                            transactionLogger.paramPut(TransactionLogger.REV_REASON, reasonCode);
                        }
                        // If we have an explicit value configured for this certificate profile, we override the the current value with this value
                        if (status.certificateProfileId != CertificateProfileConstants.CERTPROFILE_NO_PROFILE &&
                                OcspConfiguration.isRevokedUntilNextUpdateConfigured(status.certificateProfileId)) {
                            nextUpdate = OcspConfiguration.getRevokedUntilNextUpdate(status.certificateProfileId);
                        }
                        // If we have an explicit value configured for this certificate profile, we override the the current value with this value
                        if (status.certificateProfileId != CertificateProfileConstants.CERTPROFILE_NO_PROFILE &&
                                OcspConfiguration.isRevokedMaxAgeConfigured(status.certificateProfileId)) {
                            maxAge = OcspConfiguration.getRevokedMaxAge(status.certificateProfileId);
                        }
                    } else {
                        sStatus = "good";
                        certStatus = null;
                        if (!isPreSigning && transactionLogger.isEnabled()) {
                            transactionLogger.paramPut(TransactionLogger.CERT_STATUS, OCSPResponseItem.OCSP_GOOD);
                        }
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Set nextUpdate=" + nextUpdate + ", and maxAge=" + maxAge + " for certificateProfileId="
                                + status.certificateProfileId);
                    }
                    if (!isPreSigning) {
                        log.info(intres.getLocalizedMessage("ocsp.infoaddedstatusinfo", sStatus, "0x" + certId.getSerialNumber().toString(16), caCertificateSubjectDn));
                    }
                    // Issue a final OCSP Response (EN 319 411-2)
                    if (issueFinalResponse && isPreSigning) {
                        TimeZone tz = TimeZone.getTimeZone("GMT");
                        Calendar cal = Calendar.getInstance(tz);
                        cal.clear();
                        cal.set(9999, 11, 31, 23, 59, 59); // 99991231235959Z
                        nextUpdate = cal.getTimeInMillis();
                    }
                    respItem = new OCSPResponseItem(certId, certStatus, nextUpdate);
                    final OcspKeyBinding ocspKeyBinding = ocspSigningCacheEntry.getOcspKeyBinding();
                    if (ocspKeyBinding != null && ocspKeyBinding.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
                        addArchiveCutoff(respItem, ocspSigningCacheEntry.getIssuerCaCertificate(), ocspKeyBinding);
                    }
                }
 
                for (String oidstr : extensionOids) {
                    boolean useAlways = false;
                    if (oidstr.equals(alwaysUseOid)) {
                        useAlways = true;
                    }
                    ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidstr);
                    Extension extension = null;
                    if (!useAlways && req.hasExtensions()) {
                        // Only check if extension exists if we are not already bound to use it
                            extension = req.getExtension(oid);
                    }
                    //If found, or if it should be used anyway
                    if (useAlways || extension!=null) {
                        // We found an extension, call the extension class
                        if (log.isDebugEnabled()) {
                            log.debug("Found OCSP extension oid: " + oidstr);
                        }
                        OCSPExtension extObj = OcspExtensionsCache.INSTANCE.getExtensions().get(oidstr);
                        // Find the certificate from the certId
                        if (extObj != null && certificateStatusHolder != null && certificateStatusHolder.getCertificate() != null) {
                            X509Certificate cert = (X509Certificate) certificateStatusHolder.getCertificate();
                            // From EJBCA 6.2.10 and 6.3.2 the extension must perform the reverse DNS lookup by itself if needed.
                            final String remoteHost = remoteAddress;
                            // Call the OCSP extension
                            Map<ASN1ObjectIdentifier, Extension> retext = null;
                            retext = extObj.process(requestCertificates, remoteAddress, remoteHost, cert, certStatus,
                                    ocspSigningCacheEntry.getOcspKeyBinding());
                            if (retext != null) {
                                // Add the returned X509Extensions to the responseExtension we will add to the basic OCSP response
                                if (extObj.getExtensionType().contains(OCSPExtensionType.RESPONSE)) {
                                    responseExtensions.putAll(retext);
                                }
                                if (extObj.getExtensionType().contains(OCSPExtensionType.SINGLE_RESPONSE)) {
                                    respItem.addExtensions(retext);
                                }
                            } else {
                                log.error(intres.getLocalizedMessage("ocsp.errorprocessextension", extObj.getClass().getName(),
                                        extObj.getLastErrorCode()));
                            }
                        }
                    }
                }
                responseList.add(respItem);
            }
            if (addExtendedRevokedExtension) { 
                // id-pkix-ocsp-extended-revoke OBJECT IDENTIFIER ::= {id-pkix-ocsp 9}
                final ASN1ObjectIdentifier extendedRevokedOID = OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke;
                try {
                    responseExtensions.put(extendedRevokedOID, new Extension(extendedRevokedOID, false, DERNull.INSTANCE.getEncoded() ));
                } catch (IOException e) {
                    throw new IllegalStateException("Could not get encoding from DERNull.", e);
                }
            }
            if (ocspSigningCacheEntry != null) {
                // Add standard response extensions
                responseExtensions.putAll(getStandardResponseExtensions(req, ocspSigningCacheEntry));
                
                // Add responseExtensions
                Extensions exts = new Extensions(responseExtensions.values().toArray(new Extension[0]));
                // generate the signed response object
                BasicOCSPResp basicresp = signOcspResponse(req, responseList, exts, ocspSigningCacheEntry, producedAt);
                signerCert = ocspSigningCacheEntry.getSigningCertificate();
                ocspResponse = responseGenerator.build(OCSPRespBuilder.SUCCESSFUL, basicresp);
                if (!isPreSigning && auditLogger.isEnabled()) {
                    auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
                }
                if (!isPreSigning && transactionLogger.isEnabled()) {
                    transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SUCCESSFUL);
                }
            } else {
                // Only unknown CAs in requests and no default responder's cert, return an unsigned response
                if (log.isDebugEnabled()) {
                    log.debug(intres.getLocalizedMessage("ocsp.errornocacreateresp"));
                }
                ocspResponse = responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
                if (!isPreSigning && auditLogger.isEnabled()) {
                    auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                }
                if (!isPreSigning && transactionLogger.isEnabled()) {
                    transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
                }
            }
        } catch (SignRequestException e) {
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.SIG_REQUIRED, null);
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.SIG_REQUIRED);
            }
        } catch (IllegalNonceException e) {
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null);
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
            }
        } catch (SignRequestSignatureException e) {
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.UNAUTHORIZED, null);
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.UNAUTHORIZED);
            }
        } catch (InvalidAlgorithmException e) {
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(PatternLogger.PROCESS_TIME, PatternLogger.PROCESS_TIME);
            }
            String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg); // No need to log the full exception here
            // RFC 2560: responseBytes are not set on error.
            ocspResponse = responseGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null);
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.paramPut(TransactionLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.STATUS, OCSPRespBuilder.MALFORMED_REQUEST);
            }
        } catch (NoSuchAlgorithmException | CertificateException | CryptoTokenOfflineException e) {
            ocspResponse = processDefaultError(isPreSigning, responseGenerator, transactionLogger, auditLogger, e);
        }
        try {
            respBytes = ocspResponse.getEncoded();
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.paramPut(AuditLogger.OCSPRESPONSE, StringTools.hex(respBytes));
                auditLogger.writeln();
                auditLogger.flush();
            }
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.writeln();
                transactionLogger.flush();
            }
            if (OcspConfiguration.getLogSafer()) {
                // See if the Errorhandler has found any problems
                if (hasErrorHandlerFailedSince(startTime)) {
                    log.info("ProbableErrorhandler reported error, cannot answer request");
                    // RFC 2560: responseBytes are not set on error.
                    ocspResponse = responseGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);

                }
            }
        } catch (IOException e) {
            log.error("Unexpected IOException caught.", e);
            if (!isPreSigning && transactionLogger.isEnabled()) {
                transactionLogger.writeln();
                transactionLogger.flush();
            }
            if (!isPreSigning && auditLogger.isEnabled()) {
                auditLogger.writeln();
                auditLogger.flush();
            }
        }
        
        if (serialNrForResponseStore != null && caIdForResponseStore != 0 && 
                ocspResponse.getStatus() == OCSPRespBuilder.SUCCESSFUL) {
            try {
                storeOcspResponse(caIdForResponseStore, serialNrForResponseStore, ocspResponse);
            } catch (OCSPException | IOException e) {
                // Log the error and reply anyway
                log.warn("Error storing OCSP response for certificate with serialNr '" + serialNrForResponseStore);
            }
        }
        return new OcspResponseInformation(ocspResponse, maxAge, signerCert);
    }
    
    private int fetchCertStatus(org.bouncycastle.cert.ocsp.CertificateStatus certStatus) {
        if (Objects.isNull(certStatus)) {
            return OCSPResponseItem.OCSP_GOOD;
        } else if (certStatus instanceof RevokedStatus) {
            return OCSPResponseItem.OCSP_REVOKED;
        } else {
            return OCSPResponseItem.OCSP_UNKNOWN;
        }
    }

    private void storeOcspResponse(final int caId, final String serialNr, final OCSPResp ocspResponse) throws OCSPException, IOException {
        // Redundantly storing producedAt and nextUpdate, next to the canned response itself for faster querying. 
        // Assuming this is a single response (we don't store it otherwise), we can safely pick nextUpdate from first index.
        long producedAt = ((BasicOCSPResp)ocspResponse.getResponseObject()).getProducedAt().getTime();
        Long nextUpdate = null;
        final Date nextUpdateDate = ((BasicOCSPResp)ocspResponse.getResponseObject()).getResponses()[0].getNextUpdate();
        if (nextUpdateDate == null) {
            log.debug("Not persisting OCSP Response. nextUpdate is set to null");
            return;
        }
        nextUpdate = nextUpdateDate.getTime();
        final OcspResponseData responseData = new OcspResponseData(UUID.randomUUID().toString(), caId, serialNr, producedAt, nextUpdate, ocspResponse.getEncoded());
        ocspDataSession.storeOcspData(responseData);
        publishOcspResponse(caId, responseData);
    }
    
    private void publishOcspResponse(final int caId, final OcspResponseData responseData) {
        AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(
                new UsernamePrincipal(OcspResponseGeneratorSessionBean.class.getSimpleName()));
        CAInfo caInfo = caSession.getCAInfoInternal(caId);
        Collection<Integer> cAPublishers = caInfo.getCRLPublishers();

        if (CollectionUtils.isEmpty(cAPublishers)) {
            return; // Just return if no publishers set for the CA.
        }
        
        CompletableFuture.runAsync(() -> {
            try {
                publisherSession.storeOcspResponses(authenticationToken, cAPublishers, responseData);
            } catch (PublisherException | AuthorizationDeniedException e) {
                log.warn("Error publishing OCSP response data for certificate with caId '" + caId, e);
            } 
        });
    }

    private void addArchiveCutoff(final OCSPResponseItem respItem, final X509Certificate issuer, final OcspKeyBinding ocspKeyBinding) {
        try {
            final long archiveCutoffDate = ocspKeyBinding.getUseIssuerNotBeforeAsArchiveCutoff() ?
                    issuer.getNotBefore().getTime() : new Date().getTime() - ocspKeyBinding.getRetentionPeriod().getLong();
            final DEROctetString encodedValue = new DEROctetString(new ASN1GeneralizedTime(new Date(archiveCutoffDate)));
            final Extension archiveCutoffExtension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, false, encodedValue);
            respItem.addExtensions(Collections.singletonMap(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff, archiveCutoffExtension));
            if (log.isDebugEnabled()) {
                if (ocspKeyBinding.getUseIssuerNotBeforeAsArchiveCutoff()) {
                    log.debug("Added ETSI EN 319411-2, CSS-6.3.10-10 id-pkix-ocsp-archive-cutoff (issuer notBefore = " + archiveCutoffDate
                            + ") to OCSP response with cert ID serial number "
                            + respItem.getCertID().getSerialNumber().toString(16) + ".");
                } else {
                    log.debug("Added id-pkix-ocsp-archive-cutoff (producedAt - " + ocspKeyBinding.getRetentionPeriod().getLong() + " = "
                            + archiveCutoffDate + ") to OCSP response with cert ID serial number "
                            + respItem.getCertID().getSerialNumber().toString(16) + ".");
                }
            }
        } catch (final IOException e) {
            throw new IllegalStateException("An error occurred when constructing the id-pkix-ocsp-archive-cutoff extension.", e);
        }
    }

    /**
     * returns a Map of responseExtensions to be added to the BacisOCSPResponseGenerator with <code>
     * X509Extensions exts = new X509Extensions(table);
     * basicRes.setResponseExtensions(responseExtensions);
     * </code>
     * 
     * @param req the OCSP request
     * @param ocspSigningCacheEntry the OCSP signing cache entry used 
     * @return a HashMap, can be empty but not null
     * @throws IllegalNonceException if Nonce is larger than 32 bytes
     */
    private Map<ASN1ObjectIdentifier, Extension> getStandardResponseExtensions(final OCSPReq req, final OcspSigningCacheEntry ocspSigningCacheEntry)
            throws IllegalNonceException {
        HashMap<ASN1ObjectIdentifier, Extension> result = new HashMap<>();
        if (req.hasExtensions()) {
            // Table of extensions to include in the response
            // OCSP Nonce, if included in the request, the response must include the same according to RFC6960
            Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            //Check the keybinding firsthand if nonce's are enabled, if there is no keybinding (because a CA is replying), check the global value. 
            boolean nonceEnable = (ocspSigningCacheEntry.getOcspKeyBinding() != null ? ocspSigningCacheEntry.getOcspKeyBinding().isNonceEnabled() :
                ((GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID)).getNonceEnabled());
            if (null != ext && nonceEnable) {
                ASN1OctetString noncestr = ext.getExtnValue();
                // If we have a nonce, limit Nonce to 32 bytes to avoid chosen-prefix attack on hash collisions.
                // See https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/x3TOIJL7MGw
                // https://www.rfc-editor.org/rfc/rfc8954.txt
                if ( (noncestr != null) && (noncestr.getOctets() != null)) {
                    byte[] nonceoctets;
                    try {
                        // An extensions is wrapped in an octet string, this means that the nonce which is an octet string
                        // is also wrapped in the extension octet string, the parsedValue is hence an octet string
                        nonceoctets = ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();
                    } catch (IllegalArgumentException e) {
                        // It seems nonce is not properly encoded as an ASN1 Octet String. We believe this happens when wrongly not wrapped
                        // A proper Nonce extension value is an OctetString wrapped in an OctetString, Nonce is an OctetString and the Extension
                        // wraps the value in an OctetString.
                        // Anyhow, let this pass by (let broken clients work), but check the value of the invalid bytes
                        log.info("Non-parseable Nonce Octet String, invalid OCSP extension from client, letting is pass but checking the number of bytes raw");
                        nonceoctets = noncestr.getOctets();
                    }
                    if (nonceoctets != null && (nonceoctets.length > 32 || nonceoctets.length < 1)) {
                        log.info("Received OCSP request with Nonce larger than 32 bytes, rejecting.");
                        throw new IllegalNonceException("Nonce too large");
                    }
                }
                result.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
            }
        }
        return result;
    }

    /**
     * This method handles cache misses where there exists an active key binding which hasn't been cached.
     * 
     * @param certId the CertificateID for the certificate being requested. 
     * @return the now cached entry, or null if none was found. 
     */
    private OcspSigningCacheEntry findAndAddMissingCacheEntry(CertificateID certId, boolean isMsCaCompatible) throws CertificateEncodingException {
        OcspSigningCacheEntry ocspSigningCacheEntry = null;
        for (final int internalKeyBindingId : internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingDataSession.getInternalKeyBinding(internalKeyBindingId);
            if (ocspKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                X509Certificate ocspCertificate = (X509Certificate) certificateStoreSession
                        .findCertificateByFingerprint(ocspKeyBinding.getCertificateId());
                if (ocspCertificate == null) {
                    // There may be key binding with missing certificates normally (waiting for certificate response?), so don't spam the log
                    if (log.isDebugEnabled()) {
                        log.debug("Could not find certificate for OCSP Key Binding '" + ocspKeyBinding.getName() + "'. Certificate fingerprint: "
                                + ocspKeyBinding.getCertificateId());
                    }
                } else {
                    X509Certificate issuingCertificate = certificateStoreSession
                            .findLatestX509CertificateBySubject(CertTools.getIssuerDN(ocspCertificate));
                    if (issuingCertificate == null) {
                        // There may be key binding with missing certificates normally (waiting for certificate response?), so don't spam the log
                        if (log.isDebugEnabled()) {
                            log.info("Could not find issuer certificate for OCSP Key Binding '" + ocspKeyBinding.getName() + "'. Issuer DN: "
                                    + ocspKeyBinding.getCertificateId());
                        }
                    } else {
                        if (!isMsCaCompatible) { // Normal CA case
                            try {
                                if (certId.matchesIssuer(new JcaX509CertificateHolder(issuingCertificate), new BcDigestCalculatorProvider())) {
                                    //We found it! Unless it's not active, or something else was wrong with it. 
                                    ocspSigningCacheEntry = makeOcspSigningCacheEntry(ocspCertificate, ocspKeyBinding);
                                    //If it was all right, add it to the cache for future use.
                                    if (ocspSigningCacheEntry != null) {
                                        OcspSigningCache.INSTANCE.addSingleEntry(ocspSigningCacheEntry);
                                        break;
                                    }
                                }
                                
                                for(InternalKeyBindingTrustEntry signOnBehalfEntry: ocspKeyBinding.getSignOcspResponseOnBehalf()) {
                                    CAData caData = caSession.findById(signOnBehalfEntry.getCaId());
                                    if(!(caData.getCA().getCACertificate() instanceof X509Certificate)) {
                                        continue;
                                    }
                                    issuingCertificate = (X509Certificate) caData.getCA().getCACertificate();
                                    // repeating same logic as before
                                    if (certId.matchesIssuer(new JcaX509CertificateHolder(issuingCertificate), new BcDigestCalculatorProvider())) {
                                        ocspSigningCacheEntry = makeOcspSigningCacheEntry(ocspCertificate, ocspKeyBinding);

                                        if (ocspSigningCacheEntry != null) {
                                            OcspSigningCache.INSTANCE.addSingleEntry(ocspSigningCacheEntry);
                                            break;
                                        }
                                    }
                                }
                                
                                if (ocspSigningCacheEntry != null) {
                                    break;
                                }
                                
                            } catch (OCSPException e) {
                                throw new IllegalStateException("Could not create BcDigestCalculatorProvider", e);
                            }
                        } else { // MS Compatible CA case
                            
                            List<Certificate> activeCaCertificates = certificateStoreSession.findCertificatesBySubjectAndIssuer(CertTools.getSubjectDN(issuingCertificate),
                                    CertTools.getIssuerDN(issuingCertificate), true);
                            
                            final byte[] currentIssuingCertSubjectKeyId = getAuthorityKeyIdentifier(issuingCertificate);

                            for(Certificate cert : activeCaCertificates) {
                                final byte[] certificateFromRequestSubjectKeyId = getAuthorityKeyIdentifier((X509Certificate) cert);

                                try {
                                    if (StringUtils.equals(new String(Hex.encode(certificateFromRequestSubjectKeyId)),
                                            new String(Hex.encode(currentIssuingCertSubjectKeyId)))
                                            && certId.matchesIssuer(new JcaX509CertificateHolder(issuingCertificate), new BcDigestCalculatorProvider())) {
                                        //We found it! Unless it's not active, or something else was wrong with it. 
                                        ocspSigningCacheEntry = makeOcspSigningCacheEntry(ocspCertificate, ocspKeyBinding);
                                        //If it was all right, add it to the cache for future use.
                                        if (ocspSigningCacheEntry != null) {
                                            OcspSigningCache.INSTANCE.addSingleEntry(ocspSigningCacheEntry);
                                            break;
                                        }
                                    }
                                    
                                    for(InternalKeyBindingTrustEntry signOnBehalfEntry: ocspKeyBinding.getSignOcspResponseOnBehalf()) {
                                        CAData caData = caSession.findById(signOnBehalfEntry.getCaId());
                                        if(!(caData.getCA().getCACertificate() instanceof X509Certificate)) {
                                            continue;
                                        }
                                        issuingCertificate = (X509Certificate) caData.getCA().getCACertificate();
                                        // repeating same logic as before
                                        if (certId.matchesIssuer(new JcaX509CertificateHolder(issuingCertificate), new BcDigestCalculatorProvider())) {
                                            ocspSigningCacheEntry = makeOcspSigningCacheEntry(ocspCertificate, ocspKeyBinding);

                                            if (ocspSigningCacheEntry != null) {
                                                OcspSigningCache.INSTANCE.addSingleEntry(ocspSigningCacheEntry);
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if (ocspSigningCacheEntry != null) {
                                        break;
                                    }
                                } catch (OCSPException e) {
                                    throw new IllegalStateException("Could not create BcDigestCalculatorProvider", e);
                                }
                            }
                        } 
                    }
                }
            }
        }
        return ocspSigningCacheEntry;
    }
    
    @Override
    public void preSignOcspResponse(X509Certificate cacert, final BigInteger serialNr, boolean issueFinalResponse, String certIDHashAlgorithm) {
        final OCSPReq req;
        final OCSPReqBuilder gen = new OCSPReqBuilder();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        final String remoteAddress = "127.0.0.1";
        final GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration)
                globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), remoteAddress, ocspConfiguration);
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), remoteAddress, ocspConfiguration);
        CertificateID certId;
        try {
            if (isSHA1(certIDHashAlgorithm)) {
                certId = new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, serialNr);
            } else {
                certId = new JcaCertificateID(new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)), cacert, serialNr);
            }

            gen.addRequest(certId);
            req = gen.build();
            getOcspResponse(req.getEncoded(), null, remoteAddress, null, null, auditLogger, transactionLogger, true, issueFinalResponse);
        } catch (Throwable e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorprocessreq", e.getMessage());
            log.info(errMsg);
            if (log.isDebugEnabled()) {
                log.debug(errMsg, e);
            }
        }
        
    }

    private boolean isSHA1(String algorithmName) {
        return algorithmName.equalsIgnoreCase(HashAlgorithm.getName(HashAlgorithm.sha1));
    }
    
    private BasicOCSPResp signOcspResponse(OCSPReq req, List<OCSPResponseItem> responseList, Extensions exts, 
            final OcspSigningCacheEntry ocspSigningCacheEntry, Date producedAt) throws CryptoTokenOfflineException {
        assertAcceptableResponseExtension(req);
        if (!ocspSigningCacheEntry.isSigningCertificateForOcspSigning()) {
            log.warn("Signing with non OCSP certificate (no 'OCSP Signing' Extended Key Usage) bound by OcspKeyBinding '" + ocspSigningCacheEntry.getOcspKeyBinding().getName() + "'.");
        }
        final X509Certificate signerCert = ocspSigningCacheEntry.getSigningCertificate();
        final String sigAlg = getSigAlg(req, ocspSigningCacheEntry, signerCert);
        if (log.isDebugEnabled()) {
            log.debug("Signing algorithm: " + sigAlg);
        }
        try {
            // Now we can use the returned OCSPServiceResponse to get private key and certificate chain to sign the ocsp response
            final BasicOCSPResp ocspresp = generateBasicOcspResp(exts, responseList, sigAlg, signerCert, ocspSigningCacheEntry, producedAt);
            if (CertTools.isCertificateValid(signerCert, false)) { // Don't warn about signer validity for each OCSP response...
                return ocspresp;
            } else {
                throw new OcspFailureException("Response was not validly signed.");
            }
        } catch (OCSPException ocspe) {
            throw new OcspFailureException(ocspe);
        } catch (IllegalArgumentException e) {
            log.error("IllegalArgumentException: ", e);
            throw new OcspFailureException(e);
        }
    }
    
    private BasicOCSPResp generateBasicOcspResp(Extensions exts, List<OCSPResponseItem> responses, String sigAlg,
                        X509Certificate signerCert, OcspSigningCacheEntry ocspSigningCacheEntry, Date producedAt)
                                throws OCSPException, CryptoTokenOfflineException {
        final PrivateKey signerKey = ocspSigningCacheEntry.getPrivateKey();
        final String provider = ocspSigningCacheEntry.getSignatureProviderName();
        BasicOCSPResp returnval = null;
        BasicOCSPRespBuilder basicRes = new BasicOCSPRespBuilder(ocspSigningCacheEntry.getRespId());
        if (responses != null) {
            for (OCSPResponseItem item : responses) {
                Date nextUpdate = verifyNextUpdateDate(signerCert, item.getNextUpdate());
                basicRes.addResponse(item.getCertID(), item.getCertStatus(), item.getThisUpdate(), nextUpdate, item.buildExtensions());
            }
        }
        if (exts != null) {
            @SuppressWarnings("rawtypes")
            Enumeration oids = exts.oids();
            if (oids.hasMoreElements()) {
                basicRes.setResponseExtensions(exts);
            }
        }
        final X509Certificate[] chain = ocspSigningCacheEntry.getResponseCertChain();
        if (log.isDebugEnabled()) {
            log.debug("The response certificate chain contains " + chain.length + " certificates");
        }
        /*
         * The below code breaks the EJB standard by creating its own thread pool and creating a single thread (of the HsmResponseThread 
         * type). The reason for this is that the HSM may deadlock when requesting an OCSP response, which we need to guard against. Since 
         * there is no way of performing this action within the EJB3.0 standard, we are consciously creating threads here. 
         * 
         * Note that this does in no way break the spirit of the EJB standard, which is to not interrupt EJB's transaction handling by 
         * competing with its own thread pool, since these operations have no database impact.
         */
        final Future<BasicOCSPResp> task = service.submit(new HsmResponseThread(basicRes, sigAlg, signerKey, chain, provider, producedAt));
        try {
            returnval = task.get(HsmResponseThread.HSM_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            task.cancel(true);
            throw new Error("OCSP response retrieval was interrupted while running. This should not happen", e);
        } catch (ExecutionException e) {
            task.cancel(true);
            throw new OcspFailureException("Failure encountered while retrieving OCSP response.", e);
        } catch (TimeoutException e) {
            task.cancel(true);
            throw new CryptoTokenOfflineException("HSM timed out while trying to get OCSP response", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Signing OCSP response with OCSP signer cert: " + signerCert.getSubjectDN().getName());
        }
        
        if (!returnval.getResponderId().equals(ocspSigningCacheEntry.getRespId())) {
            log.error("Response responderId does not match signer certificate responderId!");
            throw new OcspFailureException("Response responderId does not match signer certificate responderId!");
        }
        if (!ocspSigningCacheEntry.checkResponseSignatureVerified()) {
            // We only check the response signature the first time for each OcspSigningCacheEntry to detect a misbehaving HSM.
            // The client is still responsible for validating the signature, see RFC 6960 Section 3.2.2
            boolean verify;
            try {
                verify = returnval.isSignatureValid(CertTools.genContentVerifierProvider(signerCert.getPublicKey()));
            } catch (OperatorCreationException e) {
                // Very fatal error
                throw new EJBException("Can not create Jca content signer: ", e);
            }
            if (verify) {
                if (log.isDebugEnabled()) {
                    log.debug("The OCSP response is verifying.");
                }
            } else {
                log.error("The response is NOT verifying! Attempted to sign using " + CertTools.getSubjectDN(signerCert) + " but signature was not valid.");
                throw new OcspFailureException("Attempted to sign using " + CertTools.getSubjectDN(signerCert) + " but signature was not valid.");
            }
        }
        return returnval;
    }

    private Date verifyNextUpdateDate(X509Certificate signerCert, Date nextUpdate) {
        if (nextUpdate != null) {
            TimeZone tz = TimeZone.getTimeZone("GMT");
            Calendar cal = Calendar.getInstance(tz);
            cal.set(9999, 11, 31, 23, 59, 59); // 99991231235959Z
            if (nextUpdate.getTime() >= cal.getTimeInMillis()) {
                nextUpdate.setTime(cal.getTimeInMillis());
                if (log.isDebugEnabled()) {
                    log.debug("nextUpdate is larger than 9999-12-31:23.59.59 GMT, limiting value as specified in RFC5280 4.1.2.5: " + ValidityDate.formatAsUTC(nextUpdate));
                }
                return nextUpdate;
            } else if (signerCert != null && signerCert.getNotAfter().before(nextUpdate)) {
                // Adjust nextUpdate so that it can never exceed the OCSP responder signing certificate validity
                nextUpdate = signerCert.getNotAfter();
            }
            // Make validity, notBefore through notAfter, inclusive. ECA-10327.
            nextUpdate.setTime(nextUpdate.getTime() - ValidityDate.NOT_AFTER_INCLUSIVE_OFFSET);
        }
        return nextUpdate;
    }

    /**
     * Method that checks with ProbableErrorHandler if an error has happened since a certain time. Uses reflection to call ProbableErrorHandler
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

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Deprecated //Remove this method once upgrading from 5-6 is dropped
    public void adhocUpgradeFromPre60(char[] activationPassword) {
        AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
                OcspResponseGeneratorSessionBean.class.getSimpleName() + ".adhocUpgradeFromPre60"));
        // Check if there are any OcspKeyBindings already, if so return
        if (!internalKeyBindingDataSession.getIds(OcspKeyBinding.IMPLEMENTATION_ALIAS).isEmpty()) {
            return;
        }
        // If ocsp.activation.doNotStorePasswordsInMemory=true, new Crypto Tokens should not be auto-actived
        final boolean globalDoNotStorePasswordsInMemory = OcspConfiguration.getDoNotStorePasswordsInMemory();
        if (globalDoNotStorePasswordsInMemory && activationPassword == null) {
            log.info("Postponing conversion of ocsp.properties configuration to OcspKeyBindings since password is not yet available.");
            return;
        }
        log.info("No OcspKeyBindings found. Processing ocsp.properties to see if we need to perform conversion.");
        final List<InternalKeyBindingTrustEntry> trustDefaults = getOcspKeyBindingTrustDefaults();
        // Create CryptoTokens and AuthenticationKeyBinding from:
        //  ocsp.rekeying.swKeystorePath = wsKeyStore.jks
        //  ocsp.rekeying.swKeystorePassword = foo123
        //  if "ocsp.rekeying.swKeystorePath" isn't set, search the p11 slot later on for an entry with an SSL certificate and use this
        final String swKeystorePath = ConfigurationHolder.getString("ocsp.rekeying.swKeystorePath");
        final String swKeystorePassword = ConfigurationHolder.getString("ocsp.rekeying.swKeystorePassword");
        if (swKeystorePath != null && (swKeystorePassword != null || activationPassword!=null)) {
            final String password = swKeystorePassword==null ? new String(activationPassword) : swKeystorePassword;
            processSoftKeystore(authenticationToken, new File(swKeystorePath), password, password, globalDoNotStorePasswordsInMemory, trustDefaults);
        }
        if (OcspConfiguration.getP11Password() != null || activationPassword != null) {
            log.info(" Processing PKCS#11..");
            final String p11SharedLibrary = OcspConfiguration.getP11SharedLibrary();
            final String sunP11ConfigurationFile = OcspConfiguration.getSunP11ConfigurationFile();
            try {
                final String p11password = OcspConfiguration.getP11Password() == null ? new String(activationPassword) : OcspConfiguration.getP11Password();
                String cryptoTokenName = null;
                final Properties cryptoTokenProperties = new Properties();
                if (p11SharedLibrary != null && p11SharedLibrary.length()!=0) {
                    log.info(" Processing PKCS#11 with shared library " + p11SharedLibrary);
                    final String p11slot = OcspConfiguration.getP11SlotIndex();       
                    cryptoTokenProperties.put(PKCS11CryptoToken.SHLIB_LABEL_KEY, p11SharedLibrary);
                    cryptoTokenProperties.put(PKCS11CryptoToken.SLOT_LABEL_VALUE, p11slot);
                    // Guess label type in order index, number or label 
                    Pkcs11SlotLabelType type;
                    if(Pkcs11SlotLabelType.SLOT_NUMBER.validate(p11slot)) {
                        type = Pkcs11SlotLabelType.SLOT_NUMBER;
                    } else if(Pkcs11SlotLabelType.SLOT_INDEX.validate(p11slot)) {
                        type = Pkcs11SlotLabelType.SLOT_INDEX;
                    } else {
                        type = Pkcs11SlotLabelType.SLOT_LABEL;
                    }
                    cryptoTokenProperties.put(PKCS11CryptoToken.SLOT_LABEL_TYPE, type.getKey());
                    cryptoTokenName = "PKCS11 slot "+p11slot;
                } else if (sunP11ConfigurationFile != null && sunP11ConfigurationFile.length()!=0) {
                    log.info(" Processing PKCS#11 with Sun property file " + sunP11ConfigurationFile);
                    // The following properties are of interest from this file
                    // We will bravely ignore attributes.. it wouldn't be to hard for the user to change the CryptoToken's attributes file later on
                    // name=SafeNet
                    // library=/opt/PTK/lib/libcryptoki.so
                    // slot=1
                    // slotListIndex=1
                    // attributes(...) = {..} 
                    // ...
                    final Properties p11ConfigurationFileProperties = new Properties();
                    p11ConfigurationFileProperties.load(new FileInputStream(sunP11ConfigurationFile));
                    String p11slot = p11ConfigurationFileProperties.getProperty("slot");
                    cryptoTokenProperties.put(PKCS11CryptoToken.SLOT_LABEL_VALUE, p11slot);
                    // Guess label type in order index, number or label 
                    Pkcs11SlotLabelType type;
                    if(Pkcs11SlotLabelType.SLOT_NUMBER.validate(p11slot)) {
                        type = Pkcs11SlotLabelType.SLOT_NUMBER;
                    } else if(Pkcs11SlotLabelType.SLOT_INDEX.validate(p11slot)) {
                        type = Pkcs11SlotLabelType.SLOT_INDEX;
                    } else {
                        type = Pkcs11SlotLabelType.SLOT_LABEL;
                    }
                    cryptoTokenProperties.put(PKCS11CryptoToken.SLOT_LABEL_TYPE, type.getKey());
                    
                    cryptoTokenProperties.put(PKCS11CryptoToken.SHLIB_LABEL_KEY, p11ConfigurationFileProperties.getProperty("library"));
                    //cryptoTokenProperties.put(PKCS11CryptoToken.ATTRIB_LABEL_KEY, null);
                    log.warn("Any attributes(..) = { ... } will be ignored and system defaults will be used."+
                            " You should reconfigure the CryptoToken later if this is not sufficient.");
                    cryptoTokenName = "PKCS11 slot "+p11ConfigurationFileProperties.getProperty("slot", "i" + p11ConfigurationFileProperties.getProperty("slotListIndex"));
                }
                if (cryptoTokenName != null && cryptoTokenManagementSession.getIdFromName(cryptoTokenName) == null) {
                    if (!globalDoNotStorePasswordsInMemory) {
                        log.info(" Auto-activation will be used.");
                        BaseCryptoToken.setAutoActivatePin(cryptoTokenProperties, p11password, true);
                    } else {
                        log.info(" Auto-activation will not be used.");
                    }
                    final int p11CryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName,
                            PKCS11CryptoToken.class.getName(), cryptoTokenProperties, null, p11password.toCharArray());
                    // Use reflection to dig out the certificate objects for each alias so we can create an internal key binding for it
                    final Method m = BaseCryptoToken.class.getDeclaredMethod("getKeyStore");
                    m.setAccessible(true);
                    final CachingKeyStoreWrapper cachingKeyStoreWrapper = (CachingKeyStoreWrapper) m.invoke(cryptoTokenManagementSession.getCryptoToken(p11CryptoTokenId));
                    createInternalKeyBindings(authenticationToken, p11CryptoTokenId, cachingKeyStoreWrapper.getKeyStore(), trustDefaults);
                }
            } catch (Exception e) {
                log.error("", e);
            }
        }
        if (OcspConfiguration.getSoftKeyDirectoryName() != null && (OcspConfiguration.getStorePassword() != null || activationPassword != null)) {
            final String softStorePassword = OcspConfiguration.getStorePassword() == null ? new String(activationPassword) : OcspConfiguration.getStorePassword();
            final String softKeyPassword = OcspConfiguration.getKeyPassword() == null ? new String(activationPassword) : OcspConfiguration.getKeyPassword();
            final String dirName = OcspConfiguration.getSoftKeyDirectoryName();
            if (dirName != null) {
                final File directory = new File(dirName);
                if (directory.isDirectory()) {
                    log.info(" Processing Soft KeyStores..");
                    for (final File file : directory.listFiles()) {
                        processSoftKeystore(authenticationToken, file, softStorePassword, softKeyPassword, globalDoNotStorePasswordsInMemory, trustDefaults);
                    }
                }
            }
        }
    }
    
    @Deprecated //Remove this method as soon as upgrading from 5.0->6.x is dropped
    private void processSoftKeystore(AuthenticationToken authenticationToken, File file, String softStorePassword, String softKeyPassword,
            boolean doNotStorePasswordsInMemory, List<InternalKeyBindingTrustEntry> trustDefaults) {
     KeyStore keyStore;
        final char[] passwordChars = softStorePassword.toCharArray();
        // Load keystore (JKS or PKCS#12)
        try {
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(file), passwordChars);
        } catch (Exception e) {
            try {
                keyStore = KeyStore.getInstance("PKCS12", "BC");
                keyStore.load(new FileInputStream(file), passwordChars);
            } catch (Exception e2) {
                try {
                    log.info("Unable to process " + file.getCanonicalPath() + " as a KeyStore.");
                } catch (IOException e3) {
                    log.warn(e3.getMessage());
                }
                return;
            }
        }
        
        // Strip issuer certs, etc. and convert to PKCS#12
        try {
            keyStore = makeKeysOnlyP12(keyStore, passwordChars);
        } catch (Exception e) {
            throw new RuntimeException("failed to convert keystore to P12 during keybindings upgrade", e);
        }
        
        final String name = file.getName();
        if (cryptoTokenManagementSession.getIdFromName(name) != null) {
            return; // already upgraded
        }
        log.info(" Processing Soft KeyStore '" + name + "' of type " + keyStore.getType());
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // Save the store using the same password as the keys are protected with (not the store password)
            // so we don't have to replace the protection for each key
            keyStore.store(baos, softKeyPassword.toCharArray());
            final Properties cryptoTokenProperties = new Properties();
            if (!doNotStorePasswordsInMemory) {
                log.info(" Auto-activation will be used.");
                BaseCryptoToken.setAutoActivatePin(cryptoTokenProperties, softKeyPassword, true);
            } else {
                log.info(" Auto-activation will not be used.");
            }
            final int softCryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, name,
                    SoftCryptoToken.class.getName(), cryptoTokenProperties, baos.toByteArray(), softKeyPassword.toCharArray());
            createInternalKeyBindings(authenticationToken, softCryptoTokenId, keyStore, trustDefaults);
        } catch (Exception e) {
            log.warn(e.getMessage());
        }
    }
    
    /** Creates a PKCS#12 KeyStore with keys only from an JKS file (no issuer certs or trusted certs) */
    @Deprecated  //Remove this method as soon as upgrading from 5->6 is dropped
    private KeyStore makeKeysOnlyP12(KeyStore keyStore, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, NoSuchProviderException, CertificateException, IOException {
        final KeyStore p12 = KeyStore.getInstance("PKCS12", "BC");
        final KeyStore.ProtectionParameter protParam =
            (password != null ? new KeyStore.PasswordProtection(password) : null);
        p12.load(null, password); // initialize
        
        final Enumeration<String> en = keyStore.aliases();
        while (en.hasMoreElements()) {
            final String alias = en.nextElement();
            if (!keyStore.isKeyEntry(alias)) continue;
            try {
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, protParam);
                Certificate[] chain = new Certificate[] { entry.getCertificate() };
                p12.setKeyEntry(alias, entry.getPrivateKey(), password, chain);
            } catch (UnsupportedOperationException uoe) {
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
                Certificate[] chain = new Certificate[] { entry.getCertificate() };
                p12.setKeyEntry(alias, entry.getPrivateKey(), null, chain);
            }
        }
        return p12;
    }
    
    /** Create InternalKeyBindings for Ocsp signing and SSL client authentication certs during ad-hoc upgrades. */
    @Deprecated //Remove this method as soon as upgrading from 5->6 is dropped
    private void createInternalKeyBindings(AuthenticationToken authenticationToken, int cryptoTokenId, KeyStore keyStore, List<InternalKeyBindingTrustEntry> trustDefaults) throws KeyStoreException, 
    CryptoTokenOfflineException, InternalKeyBindingNameInUseException, AuthorizationDeniedException, CertificateEncodingException, CertificateImportException, InvalidAlgorithmException, InternalKeyBindingNonceConflictException {
        final Enumeration<String> aliases = keyStore.aliases();
        boolean noAliases = true;
        while (aliases.hasMoreElements()) {
            final String keyPairAlias = aliases.nextElement();
            noAliases = false;
            log.info("Found alias " + keyPairAlias + ", trying to figure out if this is something we should convert into a new KeyBinding...");
            final Certificate[] chain = keyStore.getCertificateChain(keyPairAlias);
            if (chain == null || chain.length==0) {
                log.info("Alias " + keyPairAlias + " does not contain any certificate and will be ignored.");
                continue;   // Ignore entry
            }
            // Extract the default signature algorithm
            final String signatureAlgorithm = getSigningAlgFromAlgSelection(OcspConfiguration.getSignatureAlgorithm(), chain[0].getPublicKey());
            if (OcspKeyBinding.isOcspSigningCertificate(chain[0], 
                    (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID))) {
                // Create the actual OcspKeyBinding
                log.info("Alias " + keyPairAlias + " contains an OCSP certificate and will be converted to an OcspKeyBinding.");
                int internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, OcspKeyBinding.IMPLEMENTATION_ALIAS,
                        "OcspKeyBinding for " + keyPairAlias, InternalKeyBindingStatus.DISABLED, null, cryptoTokenId, keyPairAlias, signatureAlgorithm,
                        getOcspKeyBindingDefaultProperties(), trustDefaults);
                internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId, chain[0].getEncoded());
                internalKeyBindingMgmtSession.setStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
            } else if (AuthenticationKeyBinding.isClientSSLCertificate(chain[0], (AvailableExtendedKeyUsagesConfiguration) globalConfigurationSession.getCachedConfiguration(AvailableExtendedKeyUsagesConfiguration.CONFIGURATION_ID))) {
                log.info("Alias " + keyPairAlias + " contains an SSL client certificate and will be converted to an AuthenticationKeyBinding.");
                // We are looking for an SSL cert, use this to create an AuthenticationKeyBinding
                int internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, AuthenticationKeyBinding.IMPLEMENTATION_ALIAS,
                        "AuthenticationKeyBinding for " + keyPairAlias, InternalKeyBindingStatus.DISABLED, null, cryptoTokenId, keyPairAlias,
                        signatureAlgorithm, null, null);
                internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId, chain[0].getEncoded());
                internalKeyBindingMgmtSession.setStatus(authenticationToken, internalKeyBindingId, InternalKeyBindingStatus.ACTIVE);
            } else {
                log.info("Alias " + keyPairAlias + " contains certificate of unknown type and will be ignored.");
            }
        }
        if (noAliases) {
            log.info("No aliases to process were found in the key store.");
        }
    }

    /** @return a list of trusted signers or CAs */
    @Deprecated //This method is only used for upgrading to version 6
    private List<InternalKeyBindingTrustEntry> getOcspKeyBindingTrustDefaults() {
        // Import certificates used to verify OCSP request signatures and add these to each OcspKeyBinding's trust-list
        //  ocsp.signtrustdir=signtrustdir
        //  ocsp.signtrustvalidtime should be ignored
        final List<InternalKeyBindingTrustEntry> trustedCertificateReferences = new ArrayList<>();
        if (OcspConfiguration.getEnforceRequestSigning() && OcspConfiguration.getRestrictSignatures()) {
            // Import certificates and configure Issuer+serialnumber in trustlist for each
            final String dirName = OcspConfiguration.getSignTrustDir();
            if (dirName != null) {
                final File directory = new File(dirName);
                if (directory.isDirectory()) {
                    for (final File file : directory.listFiles()) {
                        try {
                            final List<Certificate> chain = CertTools.getCertsFromPEM(new FileInputStream(file));
                            if (!chain.isEmpty()) {
                                final String issuerDn = CertTools.getIssuerDN(chain.get(0));
                                final String subjectDn = CertTools.getSubjectDN(chain.get(0));
                                if (OcspConfiguration.getRestrictSignaturesByMethod()==OcspConfiguration.RESTRICTONSIGNER) {
                                    final int caId = issuerDn.hashCode();
                                    final BigInteger serialNumber = CertTools.getSerialNumber(chain.get(0));
                                    if(!caSession.existsCa(caId)) { 
                                        log.warn("Trusted certificate with serialNumber " + serialNumber.toString(16) +
                                                " is issued by an unknown CA with subject '" + issuerDn +
                                                "'. You should import this CA certificate as en external CA to make it known to the system.");
                                    }
                                    trustedCertificateReferences.add(new InternalKeyBindingTrustEntry(caId, serialNumber));
                                } else {
                                    final int caId = subjectDn.hashCode();
                                    if(!caSession.existsCa(caId)) { 
                                        log.warn("Trusted CA certificate with with subject '" + subjectDn +
                                                "' should be imported as en external CA to make it known to the system.");
                                    }
                                    trustedCertificateReferences.add(new InternalKeyBindingTrustEntry(caId, null));
                                }
                            }
                        } catch (CertificateException | FileNotFoundException e) {
                            log.warn(e.getMessage());
                        }
                    }
                }
            }
        }
        return trustedCertificateReferences;
    }
    
    /** @return OcspKeyBinding properties set to the current file-based configuration (per cert profile config is ignored here) */
    @SuppressWarnings("deprecation")
    private Map<String, Serializable> getOcspKeyBindingDefaultProperties() {
        // Use global config as defaults for each new OcspKeyBinding
        final Map<String, Serializable> dataMap = new HashMap<>();
        dataMap.put(OcspKeyBinding.PROPERTY_INCLUDE_CERT_CHAIN, OcspConfiguration.getIncludeCertChain());
        if (OcspConfiguration.getResponderIdType()==OcspConfiguration.RESPONDERIDTYPE_NAME) {
            dataMap.put(OcspKeyBinding.PROPERTY_RESPONDER_ID_TYPE, ResponderIdType.NAME.name());
        } else {
            dataMap.put(OcspKeyBinding.PROPERTY_RESPONDER_ID_TYPE, ResponderIdType.KEYHASH.name());
        }
        dataMap.put(OcspKeyBinding.PROPERTY_MAX_AGE, OcspConfiguration.getMaxAge(CertificateProfileConstants.CERTPROFILE_NO_PROFILE)/1000L);
        dataMap.put(OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD, OcspConfiguration.getNonExistingIsGood());
        dataMap.put(OcspKeyBinding.PROPERTY_NON_EXISTING_REVOKED, OcspConfiguration.getNonExistingIsRevoked());
        dataMap.put(OcspKeyBinding.PROPERTY_UNTIL_NEXT_UPDATE, OcspConfiguration.getUntilNextUpdate(CertificateProfileConstants.CERTPROFILE_NO_PROFILE)/1000L);
        dataMap.put(OcspKeyBinding.PROPERTY_REQUIRE_TRUSTED_SIGNATURE, OcspConfiguration.getEnforceRequestSigning());
        return dataMap;
    }
    
    @Override
    public String healthCheck() {
        final StringBuilder sb = new StringBuilder();
        // Check that there are no ACTIVE OcspKeyBindings that are not in the cache before checking usability..
        for (InternalKeyBindingInfo internalKeyBindingInfo : internalKeyBindingMgmtSession
                .getAllInternalKeyBindingInfos(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
            if (internalKeyBindingInfo.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                final Certificate ocspCertificate = certificateStoreSession.findCertificateByFingerprint(internalKeyBindingInfo.getCertificateId());
                final X509Certificate issuingCertificate = certificateStoreSession.findLatestX509CertificateBySubject(CertTools
                        .getIssuerDN(ocspCertificate));
                OcspSigningCacheEntry ocspSigningCacheEntry = null;
                OcspDataConfigCacheEntry configCacheEntry = null;
                if (issuingCertificate != null) {
                    final List<CertificateID> certIds = OcspSigningCache.getCertificateIDFromCertificate(issuingCertificate);
                    // We only need to use the first certId type to find an entry in the cache, certIds.get(0), since all of them should be in the cache
                    ocspSigningCacheEntry = OcspSigningCache.INSTANCE.getEntry(certIds.get(0));
                    if (ocspSigningCacheEntry == null) {
                        //Could be a cache issue?
                        try {
                            
                            configCacheEntry = OcspDataConfigCache.INSTANCE.getEntry(certIds.get(0));
                            
                            if(configCacheEntry != null && configCacheEntry.isMsCaCompatible()) {
                                ocspSigningCacheEntry = findAndAddMissingCacheEntry(certIds.get(0), true);
                            } else {
                                ocspSigningCacheEntry = findAndAddMissingCacheEntry(certIds.get(0), false);
                            }
                            
                        } catch (CertificateEncodingException e) {
                           throw new IllegalStateException("Could not process certificate", e);
                        }
                    }                    
                } else {
                    log.info("Can not find issuer certificate from subject DN '"+CertTools.getIssuerDN(ocspCertificate)+"'.");
                }
                
                if (ocspSigningCacheEntry == null) {
                    final String errMsg = intres.getLocalizedMessage("ocsp.signingkeynotincache", internalKeyBindingInfo.getName());
                    sb.append('\n').append(errMsg);
                    log.error(errMsg);
                }
            }
        }
        if(!sb.toString().equals("")) {
            return sb.toString();
        }
        try {
            final Collection<OcspSigningCacheEntry> ocspSigningCacheEntries = OcspSigningCache.INSTANCE.getEntries();
            if (ocspSigningCacheEntries.isEmpty()) {
                // Only report this in the server log. It is not an erroneous state to have no ACTIVE OcspKeyBindings.
                if (log.isDebugEnabled()) {
                    log.debug(intres.getLocalizedMessage("ocsp.errornosignkeys"));
                }
            } else {
                for (OcspSigningCacheEntry ocspSigningCacheEntry : ocspSigningCacheEntries) {
                    // Only verify non-CA responders
                    final X509Certificate ocspSigningCertificate = ocspSigningCacheEntry.getOcspSigningCertificate();
                    if (ocspSigningCertificate == null) {
                        continue;
                    }
                    final String subjectDn = CertTools.getSubjectDN(ocspSigningCacheEntry.getCaCertificateChain().get(0));
                    final String serialNumberForLog = CertTools.getSerialNumberAsString(ocspSigningCacheEntry.getOcspSigningCertificate());
                    final String errMsg = intres.getLocalizedMessage("ocsp.errorocspkeynotusable", subjectDn, serialNumberForLog);
                    final PrivateKey privateKey = ocspSigningCacheEntry.getPrivateKey();
                    if (privateKey == null) {
                        sb.append('\n').append(errMsg);
                        log.error("No key available. " + errMsg);
                        continue;
                    }
                    if (OcspConfiguration.getHealthCheckCertificateValidity() && !CertTools.isCertificateValid(ocspSigningCertificate, true) ) {
                        sb.append('\n').append(errMsg);
                        continue;
                    }
                    if (OcspConfiguration.getHealthCheckSignTest()) {
                        try {
                            final String providerName = ocspSigningCacheEntry.getSignatureProviderName();
                            KeyTools.testKey(privateKey, ocspSigningCertificate.getPublicKey(), providerName);
                        } catch (InvalidKeyException e) {
                            // thrown by testKey
                            sb.append('\n').append(errMsg);
                            log.error("Key not working. SubjectDN '"+subjectDn+"'. Error comment '"+errMsg+"'. Message '"+e.getMessage());
                            continue;                   
                        }
                    }
                    if (log.isDebugEnabled()) {
                        final String name = ocspSigningCacheEntry.getOcspKeyBinding().getName();
                        log.debug("Test of \""+name+"\" OK!");                          
                    }
                }
            }
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage("ocsp.errorloadsigningcerts");
            log.error(errMsg, e);
            sb.append(errMsg).append(": ").append(errMsg);
        }
        return sb.toString();
    }

}

