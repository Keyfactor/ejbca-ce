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
package org.cesecore.certificates.ocsp.standalone;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseSessionBean;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.ocsp.standalone.exception.StandaloneOcspInitializationException;
import org.cesecore.certificates.ocsp.standalone.keys.CardKeys;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.log.SaferAppenderListener;
import org.cesecore.util.log.SaferDailyRollingFileAppender;

/**  
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "StandaloneOcspResponseGeneratorSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class StandaloneOcspResponseGeneratorSessionBean extends OcspResponseSessionBean implements StandaloneOcspResponseGeneratorSessionLocal,
        StandaloneOcspResponseGeneratorSessionRemote, SaferAppenderListener {

    private static final Logger log = Logger.getLogger(StandaloneOcspResponseGeneratorSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private static final String hardTokenClassName = OcspConfiguration.getHardTokenClassName();
    private static final String p11SharedLibrary = OcspConfiguration.getP11SharedLibrary();

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    @Resource
    private SessionContext sessionContext;
    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    /** 
     * 
     * This class member knowingly breaks the EJB standard which forbids static volatile class members. The
     * spirit of this rule is to prohibit implementations from using mutexes in their SSBs, thus negating the
     * EJB bean pool. It doesn't take into account the need to cache data in a shared singleton, thus we have 
     * to knowingly break the standard, but not its spirit. 
     * 
     */
    private static volatile TokenAndChainCache cache;

    @PostConstruct
    public void init() throws AuthorizationDeniedException {
        if (OcspConfiguration.getLogSafer() == true) {

            SaferDailyRollingFileAppender.addSubscriber(this);
            log.info("added us as subscriber" + SaferDailyRollingFileAppender.class.getCanonicalName());
        }

        timerService = sessionContext.getTimerService();

        if (cache == null) {
            cache = new TokenAndChainCache();
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
        try {
            reloadTokenAndChainCache();
        } catch (AuthorizationDeniedException e) {
            throw new Error("Could not authorize using internal admin.");
        }
        Integer timerInfo = (Integer) timer.getInfo();
        addTimer(OcspConfiguration.getSignTrustValidTimeInSeconds(), timerInfo);
    }

    /**
     * Adds a timer to the bean
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private Timer addTimer(long interval, Integer id) {
        if (log.isDebugEnabled()) {
            log.debug("addTimer: " + id);
        }
        return timerService.createTimer(interval, id);
    }

    /**
     * This method cancels all timers associated with this bean.
     */
    private void cancelTimers() {
        @SuppressWarnings("unchecked")
        Collection<Timer> timers = timerService.getTimers();
        for (Timer timer : timers) {
            timer.cancel();
        }
    }

    @Override
    public void reloadTokenAndChainCache() throws AuthorizationDeniedException {
        if (OcspConfiguration.getDoNotStorePasswordsInMemory()) {
            throw new Error("Call for reloading token and chain cache without password, yet passwords may not be stored in memory.");
        }
        // Cancel any waiting timers
        cancelTimers();
        // Schedule a new timer
        addTimer(OcspConfiguration.getSignTrustValidTimeInSeconds(), cache.hashCode());

        loadPrivateKeys(OcspConfiguration.getP11Password(), OcspConfiguration.getStorePassword(), OcspConfiguration.getKeyPassword());

    }

    @Override
    public void reloadTokenAndChainCache(AuthenticationToken authenticationToken, String password) {
        loadPrivateKeys(password, password, password);
    }

    private void loadPrivateKeys(String p11Password, String p12StorePassword, String p12KeyPassword) {
        // Verify card key holder
        if (CardKeyHolder.INSTANCE.getCardKeys() == null) {
            log.info(intres.getLocalizedMessage("ocsp.classnotfound", hardTokenClassName));
        }
        Map<Integer, CryptoTokenAndChain> newCache = new ConcurrentHashMap<Integer, CryptoTokenAndChain>();
        try {
            // If P11 or P11 emulation isn't present, skip this step.
            if (p11SharedLibrary != null) {
                newCache.putAll(loadFromP11HSM(p11Password));
            }
            newCache.putAll(loadFromP12(OcspConfiguration.getSoftKeyDirectoryName(), p12StorePassword, p12KeyPassword));
            X509Certificate latestCertificate = certificateStoreSession.findLatestX509CertificateBySubject(OcspConfiguration.getDefaultResponderId());
            // We only need issuerNameHash and issuerKeyHash from certId
            cache.updateCache(newCache, new CertificateID(CertificateID.HASH_SHA1, latestCertificate, new BigInteger("1")));
        } catch (Exception e) {
            throw new StandaloneOcspInitializationException("Could not load private keys", e);
        }

    }

    /**
     * Creates a PKCS11CryptoToken and extracts all the certificate chains from it.
     * 
     * @param p11Password Password to the P11 slot.
     * @return a map of CryptoTokenChain objects loaded from the HSM
     * @throws CryptoTokenOfflineException
     */
    private Map<Integer, CryptoTokenAndChain> loadFromP11HSM(String p11Password) throws CryptoTokenOfflineException {

        Properties p11Properties = new Properties();
        p11Properties.setProperty(PKCS11CryptoToken.SLOT_LIST_INDEX_LABEL_KEY, OcspConfiguration.getP11SlotIndex());
        p11Properties.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, p11SharedLibrary);
        p11Properties.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, OcspConfiguration.getSunP11ConfigurationFile());
        // p11Properties.setProperty(PKCS11CryptoToken.PASSWORD_LABEL_KEY, p11Password);

        try {
            PKCS11CryptoToken cryptoToken = new PKCS11CryptoToken();
            cryptoToken.init(p11Properties, null, 11);
            try {
                cryptoToken.activate(p11Password.toCharArray());
            } catch (CryptoTokenAuthenticationFailedException e) {
                throw new StandaloneOcspInitializationException("Authentication failed for P11 cache.", e);
            }
            return buildCacheFromCryptoToken(cryptoToken);
        } catch (InstantiationException e) {
            throw new StandaloneOcspInitializationException("Could not create PKCS11CryptoToken", e);
        } catch (KeyStoreException e) {
            throw new StandaloneOcspInitializationException("Keystore was not activated for P11.", e);
        }

    }

    private Map<Integer, CryptoTokenAndChain> loadFromP12(String directoryName, String storePassword, String keyPassword) throws KeyStoreException,
            CryptoTokenOfflineException {
        SoftCryptoToken cryptoToken = new SoftCryptoToken();

        Properties p12Properties = new Properties();
        p12Properties.put("ca.keystorepass", storePassword);

        Map<Integer, CryptoTokenAndChain> result = new HashMap<Integer, CryptoTokenAndChain>();

        File p12Directory = new File(directoryName);
        if (!p12Directory.exists()) {
            log.warn("Soft key direktory " + directoryName + " does not exist.");
        } else if (!p12Directory.isDirectory()) {
            log.warn("Soft key directory was not a directory.");
        } else if (p12Directory.listFiles().length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No files in soft key directory.");
            }
        } else {
            for (File p12File : p12Directory.listFiles()) {
                byte[] data = new byte[(int) p12File.length()];
                try {
                    FileInputStream fileInputStream = new FileInputStream(p12File);
                    try {
                        fileInputStream.read(data);
                    } finally {
                        fileInputStream.close();
                    }
                    cryptoToken.init(p12Properties, data, 11);
                    try {
                        cryptoToken.activate(keyPassword.toCharArray());
                        result.putAll(buildCacheFromCryptoToken(cryptoToken));
                    } catch (CryptoTokenAuthenticationFailedException e) {
                        throw new StandaloneOcspInitializationException("Store password was incorrect.", e);
                    }
                } catch (IOException e) {
                    log.warn("Could not load file " + p12File);
                }

            }
        }
        return result;

    }

    private Map<Integer, CryptoTokenAndChain> buildCacheFromCryptoToken(CryptoToken cryptoToken) throws KeyStoreException,
            CryptoTokenOfflineException {
        Map<Integer, CryptoTokenAndChain> result = new HashMap<Integer, CryptoTokenAndChain>();
        // For each alias, create a CryptoTokenAndChain
        Enumeration<String> aliases = cryptoToken.getAliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            PublicKey key = cryptoToken.getPublicKey(alias);
            byte[] subjectKeyId = KeyTools.createSubjectKeyId(key).getKeyIdentifier();
            // Locate the latest OCSP certificate
            final X509Certificate latestOcspCertificate = findLatestX509Certificate(certificateStoreSession
                    .findCertificatesBySubjectKeyId(subjectKeyId));
            // No certificate associated with this subject key ID was an OCSP certificate, don't continue.
            if (latestOcspCertificate != null) {
                // Create the certificate chain from the cryptotoken.
                List<X509Certificate> certificateChain = new ArrayList<X509Certificate>();
                // Add it to the chain, and follow it all the way up.
                certificateChain.add(latestOcspCertificate);
                X509Certificate parent = latestOcspCertificate;
                if (OcspConfiguration.getIncludeCertChain()) {
                    // If this value is true, include the whole certificate chain.
                    while (!CertTools.getIssuerDN(parent).equals(CertTools.getSubjectDN(parent))) {
                        parent = certificateStoreSession.findLatestX509CertificateBySubject(CertTools.getIssuerDN(parent));
                        certificateChain.add(parent);
                    }
                } else {
                    // Otherwise, just the signing CA.
                    parent = certificateStoreSession.findLatestX509CertificateBySubject(CertTools.getIssuerDN(parent));
                    certificateChain.add(parent);
                }
                if (certificateChain.size() >= 2) {
                    CertificateID certId = null;
                    try {
                        // The issuing CA's certificate must by definition be in spot 1 in the chain.
        				// We only need issuerNameHash and issuerKeyHash from certId
                        certId = new CertificateID(CertificateID.HASH_SHA1, certificateChain.get(1), new BigInteger("1"));
                    } catch (OCSPException e) {
                        throw new OcspFailureException(e);
                    }
                    result.put(TokenAndChainCache.keyFromCertificateID(certId),
                            new CryptoTokenAndChain(cryptoToken, certificateChain.toArray(new X509Certificate[certificateChain.size()]), alias));
                } else {
                    log.warn("No issuer found in database for OCSP Certificate with subject key ID " + new String(Hex.encode(subjectKeyId))
                            + " issued by " + CertTools.getIssuerDN(latestOcspCertificate));
                }
            } else {
                log.warn("No OCSP certificate found for subject key ID " + new String(Hex.encode(subjectKeyId)));
            }
        }
        return result;
    }

    private X509Certificate findLatestX509Certificate(Collection<Certificate> certificates) {
        X509Certificate latestOcspCertificate = null;
        for (Certificate certificate : certificates) {
            X509Certificate x509Certificate = (X509Certificate) certificate;
            if (isOCSPCert(x509Certificate)) {
                if (latestOcspCertificate == null) {
                    latestOcspCertificate = x509Certificate;
                } else if (CertTools.getNotBefore(x509Certificate).after(CertTools.getNotBefore(latestOcspCertificate))) {
                    latestOcspCertificate = x509Certificate;
                }
            }
        }
        return latestOcspCertificate;
    }

    /**
     * Is OCSP extended key usage set for a certificate?
     * 
     * @param cert to check.
     * @return true if the extended key usage for OCSP is check
     */
    private boolean isOCSPCert(X509Certificate cert) {
        final String ocspKeyUsage = "1.3.6.1.5.5.7.3.9";
        final List<String> keyUsages;
        try {
            keyUsages = cert.getExtendedKeyUsage();
        } catch (CertificateParsingException e) {
            return false;
        }
        return keyUsages != null && keyUsages.contains(ocspKeyUsage);
    }

    @Override
    protected void initiateIfNecessary() {
        /**
         * The timer service is only started if we may store passwords in memory
         */
        if (timerService.getTimers().size() > 0 && !OcspConfiguration.getDoNotStorePasswordsInMemory()) {
            try {
                reloadTokenAndChainCache();
            } catch (AuthorizationDeniedException e) {
                throw new Error("Could not reload token and chain cache using internal admin.", e);
            }
        }
    }

    @Override
    protected TokenAndChainCache getTokenAndChainCache() {
        return cache;
    }

}

enum CardKeyHolder {
    INSTANCE;

    private CardKeys cardKeys = null;

    private CardKeyHolder() {
        Logger log = Logger.getLogger(CardKeyHolder.class);
        try {
            this.cardKeys = (CardKeys) StandaloneOcspResponseGeneratorSessionBean.class.getClassLoader()
                    .loadClass(OcspConfiguration.getHardTokenClassName()).newInstance();
            this.cardKeys.autenticate(OcspConfiguration.getCardPassword());
        } catch (Exception e) {
            log.info("Could not create CardKeyHolder", e);
        }
    }

    public CardKeys getCardKeys() {
        return cardKeys;
    }

}
