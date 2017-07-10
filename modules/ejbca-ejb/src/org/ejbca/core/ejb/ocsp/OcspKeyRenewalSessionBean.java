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

import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.NoSuchObjectLocalException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerConfig;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.certificates.ocsp.cache.OcspSigningCache;
import org.cesecore.certificates.ocsp.cache.OcspSigningCacheEntry;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keybind.impl.ClientX509KeyManager;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyRenewalFailedException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.BasicMatch;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspKeyRenewalSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspKeyRenewalSessionBean implements OcspKeyRenewalSessionLocal, OcspKeyRenewalSessionRemote {

    private static final Logger log = Logger.getLogger(OcspKeyRenewalSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private static final long NO_SAFETY_MARGIN = Long.MAX_VALUE/1000;
    
    private static volatile Integer timerId = null;

    // TODO: See if we can create local business methods for all calls where this is required
    private static final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "OCSP key renewal"));

    @EJB
    private OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    
    @Resource
    private SessionContext sessionContext;

    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    @PostConstruct
    public void postConstruct() {
        timerService = sessionContext.getTimerService();
        //Just do this once
        if (timerId == null) {
            synchronized (this) {
                if (timerId == null) {
                    // Any weak random number is fine
                    timerId = new Random().nextInt();
                }
            }
        }
    }
    
    /**
     * 
     * 
     * @param signerSubjectDN signerSubjectDN subject DN of the signing key to be renewed. The string "all" will result in all keys being renewed
     * @param safetyMargin the number of seconds before actual expiration that a keystore should be renewed
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws InvalidKeyException if the public key in the tokenAndChain can not be used to verify a string signed by the private key, because the key 
     * is wrong or the signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     */
    private synchronized void renewKeyStores(String signerSubjectDN, long safetyMargin) throws InvalidKeyException,
            CryptoTokenOfflineException {
        //Cancel all running timers
        cancelTimers();
        try {
            final EjbcaWS ejbcaWS = getEjbcaWS();
            if (ejbcaWS == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not locate a suitable web service for automatic OCSP key/certificate renewal.");
                }
                return;
            }
            final X500Principal target;
            try {
                target = signerSubjectDN.trim().equalsIgnoreCase(RENEW_ALL_KEYS) ? null : new X500Principal(signerSubjectDN);
            } catch (IllegalArgumentException e) {
                log.error(intres.getLocalizedMessage("ocsp.rekey.triggered.dn.not.valid", signerSubjectDN));
                return;
            }
            final StringBuffer matched = new StringBuffer();
            final StringBuffer unMatched = new StringBuffer();
            final Set<Integer> processedOcspKeyBindingIds = new HashSet<Integer>();
            for (final OcspSigningCacheEntry ocspSigningCacheEntry : OcspSigningCache.INSTANCE.getEntries()) {
                // Only perform renewal for non CA signing key OCSP signers
                if (!ocspSigningCacheEntry.isUsingSeparateOcspSigningCertificate()) {
                    continue;
                }
                // Only perform renewal once for each OcspKeyBinding.
                // (the cache can map each OcspKeyBinding multiple times by SHA-1, SHA-256 and as default responder)
                final int ocspKeyBindingId = ocspSigningCacheEntry.getOcspKeyBinding().getId();
                if (!processedOcspKeyBindingIds.add(Integer.valueOf(ocspKeyBindingId))) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skipping renewal processing of OcspKeyBinding with id " + ocspKeyBindingId + " that was already processed.");
                    }
                    continue;
                }
                final X509Certificate ocspSigningCertificate = ocspSigningCacheEntry.getOcspSigningCertificate();
                final long timeLeftBeforeRenewal = ocspSigningCertificate.getNotAfter().getTime()-new Date().getTime();
                if (timeLeftBeforeRenewal < (1000 * safetyMargin)) {
                    final X500Principal src = ocspSigningCertificate.getSubjectX500Principal();
                    if (target != null && !src.equals(target)) {
                        unMatched.append(" '" + src.getName() + '\'');
                        continue;
                    }
                    matched.append(" '" + ocspSigningCertificate.getIssuerX500Principal().getName() + '\'');
                    try {
                        renewKeyStore(ejbcaWS, ocspSigningCacheEntry);
                    } catch (KeyRenewalFailedException e) {
                        String msg = intres.getLocalizedMessage("ocsp.rekey.failed.unknown.reason", target, e.getLocalizedMessage());
                        log.error(msg, e);
                        continue;
                    }
                }
            }
            if (matched.length() < 1 && target != null) {
                log.error(intres.getLocalizedMessage("ocsp.rekey.triggered.dn.not.existing", target.getName(), unMatched));
                return;
            }
            log.info(intres.getLocalizedMessage("ocsp.rekey.triggered", matched));
        } finally {
            //Set new timer to run, even if something breaks.
            addTimer(OcspConfiguration.getRekeyingUpdateTimeInSeconds());
        }
    }

    @Override
    public synchronized void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException,
            InvalidKeyException {
        renewKeyStores(signerSubjectDN, NO_SAFETY_MARGIN);
    }

    /**
     * Generate a new key pair and request a new certificate for this key pair using EJBCA WS.
     * 
     * @param ejbcaWS a reference to the remote EJBCA WS
     * @param ocspSigningCacheEntry the cached OCSP signing entry backed by an OcspKeyBinding
     * @throws InvalidKeyException if the new public key can not be used to verify a string signed by the private key, because the key is wrong or 
     * the signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws KeyRenewalFailedException if any error occurs during signing
     */
    private void renewKeyStore(EjbcaWS ejbcaWS, OcspSigningCacheEntry ocspSigningCacheEntry) throws InvalidKeyException, CryptoTokenOfflineException, KeyRenewalFailedException {
        //Generate the new key pair
        final int internalKeyBindingId = ocspSigningCacheEntry.getOcspKeyBinding().getId();
        try {
            internalKeyBindingMgmtSession.generateNextKeyPair(authenticationToken, internalKeyBindingId);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyRenewalFailedException(e);
        } catch (AuthorizationDeniedException e) {
            throw new KeyRenewalFailedException(e);
        }
        //Sign the new keypair
        final X509Certificate signedCertificate = signCertificateByCa(ejbcaWS, ocspSigningCacheEntry);
        try {
            internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId, signedCertificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new KeyRenewalFailedException(e);
        } catch (CertificateImportException e) {
            throw new KeyRenewalFailedException(e);
        } catch (AuthorizationDeniedException e) {
            throw new KeyRenewalFailedException(e);
        }
        /*
         * Replace the alias and the chain at this step. If anything bad happened prior to this step the old alias and 
         * chain are still active, and no harm done. 
         */
        ocspResponseGeneratorSession.reloadOcspSigningCache();
    }

    /**
     * Get user data for the EJBCA user that will be used when creating the cert for the new key.
     * @param signingCertificate The OCSP signing certificate to get the end entity for
     * @param caId the ID of the OCSP signing certificate issuing CA
     * 
     * @return the data
     */
    private UserDataVOWS getUserDataVOWS(EjbcaWS ejbcaWS, final X509Certificate signingCertificate, final int caId) {
        final UserMatch match = new UserMatch();
        final String subjectDN = CertTools.getSubjectDN(signingCertificate);
        final String caName = getCAName(ejbcaWS, caId);
        if (caName == null) {
            throw new InvalidParameterException("No CA found for ID: " + caId);
        }
        match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
        match.setMatchvalue(subjectDN);
        match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
        final List<UserDataVOWS> users;
        try {
            users = ejbcaWS.findUser(match);
        } catch (Exception e) {
            log.error("WS not working", e);
            return null;
        }
        if (users == null || users.size() < 1) {
            log.error(intres.getLocalizedMessage("ocsp.no.user.with.subject.dn", subjectDN));
            return null;
        }
        log.debug("at least one user found for cert with DN: " + subjectDN + " Trying to match it with CA name: " + caName);
        UserDataVOWS result = null;
        for (UserDataVOWS userData : users) {
            if (caName.equals(userData.getCaName())) {
                result = userData;
                break;
            }
        }
        if (result == null) {
            log.error("No user found for certificate '" + subjectDN + "' on CA '" + caName + "'.");
            return null;
        }
        return result;
    }

    /**
     * setting status of EJBCA user to new and setting password of user.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @param userData from {@link #getUserDataVOWS(EjbcaWS, String)}
     * @return true if success
     */
    private boolean editUser(EjbcaWS ejbcaWS, UserDataVOWS userData) {
        userData.setStatus(EndEntityConstants.STATUS_NEW);
        userData.setPassword(PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS).getNewPassword(12, 12));
        userData.setTokenType(UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        try {
            ejbcaWS.editUser(userData);
        } catch (Exception e) {
            log.error("Problem to edit user.", e);
            return false;
        }
        return true;
    }
    /**
     * Get the CA name
     * 
     * @param caId The ID of the sought CA
     * 
     * @return the name
     */
    private String getCAName(EjbcaWS ejbcaWS, int caId) {
        final Map<Integer, String> mCA = new HashMap<Integer, String>();
        try {
            for (NameAndId nameAndId : ejbcaWS.getAvailableCAs()) {
                mCA.put(Integer.valueOf(nameAndId.getId()), nameAndId.getName());
                log.debug("CA. id: " + nameAndId.getId() + " name: " + nameAndId.getName());
            }
        } catch (Exception e) {
            log.error("WS not working", e);
            return null;
        }
        return mCA.get(Integer.valueOf(caId));
    }

    /**
     * This method sends a keypair off to be signed by the CA that issued the original keychain.
     * 
     * @return a certificate that has been signed by the CA. 
     * @throws KeyRenewalFailedException if any error occurs during signing
     * @throws CryptoTokenOfflineException 
     */
    @SuppressWarnings("unchecked")
    private X509Certificate signCertificateByCa(EjbcaWS ejbcaWS, OcspSigningCacheEntry ocspSigningCacheEntry) throws KeyRenewalFailedException,
            CryptoTokenOfflineException {
        /* Construct a certification request in order to have the new keystore certified by the CA. 
         */
        //final int caId = CertTools.stringToBCDNString(tokenAndChain.getCaCertificate().getSubjectDN().toString()).hashCode();
        final int caId = CertTools.getSubjectDN(ocspSigningCacheEntry.getCaCertificateChain().get(0)).hashCode();
        final X509Certificate ocspSigningCertificate = ocspSigningCacheEntry.getOcspSigningCertificate();
        final UserDataVOWS userData = getUserDataVOWS(ejbcaWS, ocspSigningCertificate, caId);
        if (userData == null) {
            final String msg = "User data for certificate with subject DN '" + CertTools.getSubjectDN(ocspSigningCertificate) + "' was not found.";
            log.error(msg);
            throw new KeyRenewalFailedException(msg);
        }
        editUser(ejbcaWS, userData);
        final int internalKeyBindingId = ocspSigningCacheEntry.getOcspKeyBinding().getId();
        final byte[] pkcs10CertificationRequest;
        try {
            pkcs10CertificationRequest = internalKeyBindingMgmtSession.generateCsrForNextKey(authenticationToken, internalKeyBindingId, null);
        } catch (AuthorizationDeniedException e) {
            throw new KeyRenewalFailedException(e);
        }
        CertificateResponse certificateResponse;
        try {
            certificateResponse = ejbcaWS.pkcs10Request(userData.getUsername(), userData.getPassword(),
                    new String(Base64.encode(pkcs10CertificationRequest)), null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (Exception e) {
            //Way too many silly exceptions to handle, wrap instead.
            throw new KeyRenewalFailedException(e);
        }
        if (certificateResponse == null) {
            throw new KeyRenewalFailedException("Certificate Response was not received");
        }

        Collection<X509Certificate> certificates;
        try {
            certificates = (Collection<X509Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(Base64.decode(certificateResponse.getData())));
        } catch (CertificateException e) {
            throw new KeyRenewalFailedException(e);
        }
        final byte[] publicKeyBytes;
        try {
            publicKeyBytes = internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken, internalKeyBindingId);
        } catch (AuthorizationDeniedException e) {
            throw new KeyRenewalFailedException(e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Number of certificates returned from WS: " + certificates.size());
        }
        X509Certificate signedCertificate = null;
        final X509Certificate caCertificate = ocspSigningCacheEntry.getCaCertificateChain().get(0);
        final PublicKey caCertificatePublicKey = caCertificate.getPublicKey();
        for (X509Certificate certificate : certificates) {
            if (log.isDebugEnabled()) {
                log.debug("Verifying certificate with SubjectDN : '" + CertTools.getSubjectDN(certificate) +
                        "' using public key from CA certificate with subject '" + CertTools.getSubjectDN(caCertificate) +"'.");
            }
            try {
                certificate.verify(caCertificatePublicKey);
            } catch (Exception e) {
                //Ugly, but inherited from legacy code
                signedCertificate = null;
                log.error("Exception was caught when verifying certificate", e);
                continue;
            }
            // Comparing public keys is dependent on provider used, so we must ensure same provider is used for the public keys
            // Otherwise this will fail, even though it should work
            // Both certPublicKey and nextPublicKey is obtained using KeyTools.getPublicKeyFromBytes, which uses the BC provider
            final PublicKey certPublicKey = KeyTools.getPublicKeyFromBytes(certificate.getPublicKey().getEncoded());
            final PublicKey nextPublicKey = KeyTools.getPublicKeyFromBytes(publicKeyBytes);
            if (nextPublicKey.equals(certPublicKey)) {
                signedCertificate = certificate;
                break;
            } else if (log.isDebugEnabled()) {
                log.debug("Matching public keys failed: ");
                log.debug("Certificate public key: "+certificate.getPublicKey());
                log.debug("Next public key: "+nextPublicKey);
            }
        }
        if (signedCertificate == null) {
            throw new KeyRenewalFailedException("No certificate signed by correct CA generated.");
        }
        return signedCertificate;
    }

    /** @return the EJBCA WS object. */
    private EjbcaWS getEjbcaWS() {
        String webUrl = OcspConfiguration.getEjbcawsracliUrl();
        if (StringUtils.isEmpty(webUrl)) {
            // Automatic renewal is not enabled
            if (log.isDebugEnabled()) {
                log.debug("Automatic OCSP key/certificate renewal is not enabled, "+OcspConfiguration.REKEYING_WSURL+" is empty.");
            }
            return null;
        }
        final SSLSocketFactory sslSocketFactory = getSSLSocketFactory();
        if (sslSocketFactory == null) {
            log.warn("No AuthenticationKeyBinding is configured. Unable to authenticate to EJBCA WebService.");
            return null;
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
        final URL ws_url;
        try {
            ws_url = new URL(webUrl + "?wsdl");
        } catch (MalformedURLException e) {
            log.warn("Problem with URL: '" + webUrl + "'", e);
            return null;
        }
        final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        if (log.isDebugEnabled()) {
            log.debug("web service. URL: " + ws_url + " QName: " + qname);
        }
        return new EjbcaWSService(ws_url, qname).getEjbcaWSPort();
    }
    
    private SSLSocketFactory getSSLSocketFactory() {
        final List<Integer> authenticationKeyBindingIds = internalKeyBindingMgmtSession.getInternalKeyBindingIds(authenticationToken, AuthenticationKeyBinding.IMPLEMENTATION_ALIAS);
        AuthenticationKeyBinding authenticationKeyBinding = null;
        for (Integer internalKeyBindingId : authenticationKeyBindingIds) {
            try {
                final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBindingReference(authenticationToken, internalKeyBindingId);
                if (internalKeyBinding.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                    // Use first active one
                    authenticationKeyBinding = (AuthenticationKeyBinding) internalKeyBinding;
                    break;
                }
            } catch (AuthorizationDeniedException e) {
                throw new RuntimeException(e);
            }
        }
        if (authenticationKeyBinding == null) {
            return null;
        }
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(authenticationKeyBinding.getCryptoTokenId());
        final X509Certificate sslCertificate = (X509Certificate) certificateStoreSession.findCertificateByFingerprint(authenticationKeyBinding.getCertificateId());
        final List<X509Certificate> chain = new ArrayList<X509Certificate>();
        chain.add(sslCertificate);
        chain.addAll(getCaCertificateChain(sslCertificate));
        final List<X509Certificate> trustedCertificates = getListOfTrustedCertificates(authenticationKeyBinding.getTrustedCertificateReferences());
        final String alias = authenticationKeyBinding.getKeyPairAlias();
        try {
            final TrustManager trustManagers[];
            if (trustedCertificates == null || trustedCertificates.isEmpty()) {
                trustManagers = new X509TrustManager[] {new X509TrustManagerAcceptAll()};
            } else {
                throw new RuntimeException("Configurable trust not yet implemented.");
            }
            final KeyManager keyManagers[] = new X509KeyManager[] { new ClientX509KeyManager(alias, cryptoToken.getPrivateKey(alias), chain) };
            // Now construct a SSLContext using these (possibly wrapped) KeyManagers, and the TrustManagers.
            // We still use a null SecureRandom, indicating that the defaults should be used.
            final SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers, trustManagers, null);
            // Finally, we get a SocketFactory, and pass it on.
            return context.getSocketFactory();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CryptoTokenOfflineException e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private List<X509Certificate> getListOfTrustedCertificates(List<InternalKeyBindingTrustEntry> trustedCertificateReferences) {
        if (trustedCertificateReferences == null || trustedCertificateReferences.isEmpty()) {
            return null;
        }
        // TODO: Here we need to lookup all the trusted certificates from the provided references so a X509TrustManager can do verification later
        log.warn("Trusted references was non-empty, but will be ignored. (Not yet implemented.)");
        return null;
    }

    // TODO: This method also exists in OcspResponseGenSSB.. merge! to method call in certificateStoreSession
    private List<X509Certificate> getCaCertificateChain(final X509Certificate leafCertificate) {
        final List<X509Certificate> caCertificateChain = new ArrayList<X509Certificate>();
        X509Certificate currentLevelCertificate = leafCertificate;
        while (!CertTools.getIssuerDN(currentLevelCertificate).equals(CertTools.getSubjectDN(currentLevelCertificate))) {
            final String issuerDn = CertTools.getIssuerDN(currentLevelCertificate);
            currentLevelCertificate = certificateStoreSession.findLatestX509CertificateBySubject(issuerDn);
            if (currentLevelCertificate == null) {
                log.warn("Unable to build certificate chain for OCSP signing certificate with Subject DN '" +
                        CertTools.getSubjectDN(leafCertificate) + "'. CA with Subject DN '" + issuerDn + "' is missing in the database.");
                return null;
            }
            caCertificateChain.add(currentLevelCertificate);
        }
        return caCertificateChain;
    }

    /**
     * When the timer expires, this method will check through the cache and automatically renew keystore matching the predefined criteria, 
     * and which expire within the designated time frame.
     * 
     * According to JSR 220 FR (18.2.2), this method may not throw any exceptions.
     * 
     * Glassfish 2.1.1:
     * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
     * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
     * 
     * @param timer The timer whose expiration caused this notification.
     * 
     */
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
        long rekeyingUpdateTime = OcspConfiguration.getRekeyingUpdateTimeInSeconds();
        try {
            renewKeyStores(RENEW_ALL_KEYS, OcspConfiguration.getRekeyingSafetyMarginInSeconds());
        } catch (InvalidKeyException e) {
            log.error("A cached crypto token contains an invalid key pair. Stopping timers.", e);
        } catch (CryptoTokenOfflineException e) {
            //Rescheduling is handled in a finally clause in OcspKeyRenewalSessionBean.renewKeyStores(String, long)
            log.error("Crypto token was offline or unavailable during automatic update. Rescheduling a new timer in " + rekeyingUpdateTime + " seconds.", e);
        }    
        
    }

    @Override
    public void startTimer() {
        cancelTimers();
        addTimer(OcspConfiguration.getRekeyingUpdateTimeInSeconds());
    }
    
    /**
     * Adds a timer to the bean
     * 
     * @param intervalInSeconds the time from now for the next timer to fire
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private Timer addTimer(long intervalInSeconds) {
        if (log.isDebugEnabled()) {
            log.debug("addTimer: " + timerId+", "+intervalInSeconds);
        }
        return timerService.createSingleActionTimer(intervalInSeconds*1000, new TimerConfig(timerId, false));
    }

    /**
     * This method cancels all timers associated with this bean.
     */
    private void cancelTimers() {
        Collection<Timer> timers = timerService.getTimers();
        for (Timer timer : timers) {
            try {
                timer.cancel();
            } catch (NoSuchObjectLocalException e) {
            	if (log.isDebugEnabled()) {
            	    log.debug("Timer was already expired or canceled: "+timer.getInfo());
            	}
            }
        }
    }
}
