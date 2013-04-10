/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ocsp.standalone;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorSessionLocal;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyRenewalFailedException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.util.query.BasicMatch;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspKeyRenewalSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspKeyRenewalSessionBean implements OcspKeyRenewalSessionLocal, OcspKeyRenewalSessionRemote {

    private static final Logger log = Logger.getLogger(OcspKeyRenewalSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";
    private static final long NO_SAFETY_MARGIN = Long.MAX_VALUE/1000;
    
    private static volatile Integer timerId = null;

    @EJB
    private StandaloneOcspResponseGeneratorSessionLocal standaloneOcspResponseGeneratorSession;

    @Resource
    private SessionContext sessionContext;

    /**
     * No reason not to share the same EjbcaWS object between all beans. Also makes testing 
     * waaaay easier.
     */
    private static volatile EjbcaWS ejbcaWS;

    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    @PostConstruct
    /**
     * Performs postconstruct actions on this class
     * 
     * @throws KeyRenewalFailedException if WebService object could not be created, making rekeying impossible. 
     */
    public void postConstruct() throws KeyRenewalFailedException {
        if (ejbcaWS == null) {
            synchronized (this.getClass()) {
                if (ejbcaWS == null) {
                    ejbcaWS = getEjbcaWS();
                }
            }
        }
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
     * @param signerSubjectDN signerSubjectDN subject DN of the signing key to be renewed. The string "all" (as represented by the constant 
     * TokenAndChainCache.RENEW_ALL_KEYS) will result in all keys being renewed
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
            if (ejbcaWS == null) {
                log.error("Could not locate a suitable web service");
                return;
            }
            final X500Principal target;
            try {
                target = signerSubjectDN.trim().toLowerCase().equals(RENEW_ALL_KEYS) ? null : new X500Principal(signerSubjectDN);
            } catch (IllegalArgumentException e) {
                log.error(intres.getLocalizedMessage("ocsp.rekey.triggered.dn.not.valid", signerSubjectDN));
                return;
            }
            final StringBuffer matched = new StringBuffer();
            final StringBuffer unMatched = new StringBuffer();
            Collection<CryptoTokenAndChain> cacheValues = standaloneOcspResponseGeneratorSession.getCacheValues();
            for (CryptoTokenAndChain tokenAndChain : cacheValues) {
                
                final long timeLeftBeforeRenewal = tokenAndChain.getChain()[0].getNotAfter().getTime()-new Date().getTime();
                if (timeLeftBeforeRenewal < (1000 * safetyMargin)) {
                    final X500Principal src = tokenAndChain.getChain()[0].getSubjectX500Principal();
                    if (target != null && !src.equals(target)) {
                        unMatched.append(" '" + src.getName() + '\'');
                        continue;
                    }
                    matched.append(" '" + tokenAndChain.getChain()[0].getIssuerX500Principal().getName() + '\'');
                    try {
                        renewKeyStore(tokenAndChain);
                    } catch (KeyRenewalFailedException e) {
                        String msg = intres.getLocalizedMessage("ocsp.rekey.failed.unknown.reason", target, e.getLocalizedMessage());
                        log.error(msg, e);
                        continue;
                    } catch (IOException e) {
                        String msg = intres.getLocalizedMessage("ocsp.rekey.failed.unknown.reason", target, e.getLocalizedMessage());
                        log.error(msg, e);
                        continue;
                    }
                }
            }
            if (matched.length() < 1) {
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
     * 
     * @param tokenAndChain The CryptoTokenAndChain containing the keystore to renew.
     * @throws InvalidKeyException if the public key in the tokenAndChain can not be used to verify a string signed by the private key, because the key is wrong or 
     * the signature operation fails for other reasons such as a NoSuchAlgorithmException or SignatureException.
     * @throws CryptoTokenOfflineException if Crypto Token is not available or connected, or key with alias does not exist.
     * @throws KeyRenewalFailedException if any error occurs during signing
     * @throws IOException
     */
    private void renewKeyStore(CryptoTokenAndChain tokenAndChain) throws InvalidKeyException, CryptoTokenOfflineException, KeyRenewalFailedException,
            IOException {
        final X500Principal src = tokenAndChain.getChain()[0].getSubjectX500Principal();
        //Firstly, generate a new key pair and retrieve the public and private keys for future use.                

        PublicKey oldPublicKey;
        try {
            oldPublicKey = tokenAndChain.getPublicKey();
        } catch (CryptoTokenOfflineException e) {
            log.error("Crypto token was offline, could not renew key.", e);
            return;
        }
        final AlgorithmParameterSpec algorithmParameterSpec = KeyTools.getKeyGenSpec(oldPublicKey);
        if (!(algorithmParameterSpec instanceof RSAKeyGenParameterSpec)) {
            log.info("Could not rekey " + src.getName() + ". Only RSA keys may be rekeyed");
            return;
        }
        //Let the new alias be the previous alias, with a timestamp.
        String oldAlias = tokenAndChain.getAlias();
        String dateformat = "yyyy.MM.dd-HH:mm:ss";
        String dateformatRegexp = "\\d{4}\\.\\d{2}\\.\\d{2}-\\d{2}:\\d{2}:\\d{2}$";
        String timestamp = new SimpleDateFormat(dateformat).format(Calendar.getInstance().getTime());
        Matcher matcher = Pattern.compile(dateformatRegexp).matcher(oldAlias);
        //Strip the old timestamp off the end of the old alias. If none exist, then add one. 
        final String newAlias = matcher.find() ? matcher.replaceAll(timestamp) : oldAlias + "-" + timestamp;
        //Generate the new key pair
        tokenAndChain.generateKeyPair(newAlias);
        //Sign the new keypair
        X509Certificate signedCertificate = signCertificateByCa(tokenAndChain);
        //Construct the new certificate chain
        final List<X509Certificate> lCertChain = new ArrayList<X509Certificate>(Arrays.asList(tokenAndChain.getChain()));
        lCertChain.set(0, signedCertificate);
        final X509Certificate certChain[] = lCertChain.toArray(new X509Certificate[0]);
        /*
         * Replace the alias and the chain at this step. If anything bad happened prior to this step the old alias and 
         * chain are still active, and no harm done. 
         */
        tokenAndChain.renewAliasAndChain(newAlias, certChain);

    }

    /**
     * Get user data for the EJBCA user that will be used when creating the cert for the new key.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @return the data
     */
    private UserDataVOWS getUserDataVOWS(final X509Certificate signingCertificate, final int caId) {
        final UserMatch match = new UserMatch();
        final String subjectDN = CertTools.getSubjectDN(signingCertificate);
        final String caName = getCAName(caId);
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
     * Get the CA name
     * @return the name
     */
    private String getCAName(int caId) {
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
     * @param tokenAndChain the {@link CryptoTokenAndChain} object destined to have a new keypair
     * @return a certificate that has been signed by the CA. 
     * @throws KeyRenewalFailedException if any error occurs during signing
     * @throws IOException 
     * @throws CryptoTokenOfflineException 
     */
    @SuppressWarnings("unchecked")
    private X509Certificate signCertificateByCa(CryptoTokenAndChain tokenAndChain) throws KeyRenewalFailedException, IOException,
            CryptoTokenOfflineException {
        /* Construct a certification request in order to have the new keystore certified by the CA. 
         */
        final int caId = CertTools.stringToBCDNString(tokenAndChain.getCaCertificate().getSubjectDN().toString()).hashCode();
        final UserDataVOWS userData = getUserDataVOWS(tokenAndChain.getChain()[0], caId);
        if (userData == null) {
            final String msg = "User data for certificate with subject DN: " + tokenAndChain.getChain()[0].getSubjectDN() + " was not found.";
            log.error(msg);
            throw new KeyRenewalFailedException(msg);
        }
        final PKCS10CertificationRequest pkcs10;
        try {
            pkcs10 = tokenAndChain.getPKCS10CertificationRequest(SIGNATURE_ALGORITHM);
        } catch (OperatorCreationException e) {
            final String msg = "Could not create a ContentSigner";
            log.error(msg, e);
            throw new KeyRenewalFailedException(msg, e);
        }

        CertificateResponse certificateResponse;
        try {
            certificateResponse = ejbcaWS.pkcs10Request(userData.getUsername(), userData.getPassword(),
                    new String(Base64.encode(pkcs10.getEncoded())), null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
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

        X509Certificate signedCertificate = null;
        for (X509Certificate certificate : certificates) {
            try {
                certificate.verify(tokenAndChain.getCaCertificate().getPublicKey());
            } catch (Exception e) {
                //Ugly, but inherited from legacy code
                signedCertificate = null;
                log.error("Exception was caught when verifying cerficiate", e);
                continue;
            }
            if (tokenAndChain.getPublicKey().equals(certificate.getPublicKey())) {
                signedCertificate = certificate;
                break;
            }
        }
        if (signedCertificate == null) {
            throw new KeyRenewalFailedException("No certificate signed by correct CA generated.");
        }
        return signedCertificate;
    }

    @Override
    public void setEjbcaWs(EjbcaWS ejbcaWS) {
        OcspKeyRenewalSessionBean.ejbcaWS = ejbcaWS;
    }

    /**
     * Get WS object.
     * 
     * Using this method instead of EJB injection because injection fails badly. 
     * 
     * @return the EJBCA WS object.
     */
    private EjbcaWS getEjbcaWS() {
        final URL ws_url;
        String webUrl = OcspConfiguration.getEjbcawsracliUrl();
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
            log.error("A cached crypto token contains an invalid key pair.", e);
        } catch (CryptoTokenOfflineException e) {
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
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    private Timer addTimer(long intervalInSeconds) {
        if (log.isDebugEnabled()) {
            log.debug("addTimer: " + timerId);
        }
        return timerService.createTimer(intervalInSeconds*1000, timerId);
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

}
