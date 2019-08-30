/** ***********************************************************************
 *                                                                       *
 *  SignServer: The OpenSource Automated Signing Server                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 ************************************************************************ */
package org.ejbca.ui.p11ngcli.helper;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;

/**
 * 
 * @version $Id$
 *
 */
public class OneTimeThread extends OperationsThread {

    /**
     * Logger for this class
     */
    private static final Logger LOG = Logger.getLogger(OneTimeThread.class);

    private final int id;
    private final String libName;
    private final String libDir;
    private final long slotId;
    private final String pin;
    private final int warmupTime;
    private final int timeLimit;
    private final boolean useCache;
    private final String signatureAlgorithm;
    private final Map<Long, Object> publicAttributesMap;
    private final Map<Long, Object> privateAttributesMap;
    
    
    private static final String PROPERTY_SELFSIGNED_DN = "SELFSIGNED_DN";
    private static final String PROPERTY_SELFSIGNED_VALIDITY = "SELFSIGNED_VALIDITY";
    private static final String PROPERTY_SELFSIGNED_SIGNATUREALGORITHM = "SELFSIGNED_SIGNATUREALGORITHM";
    private static final long DEFAULT_VALIDITY_S = (long) 30 * 24 * 60 * 60 * 365; // 30 year in seconds
    private static final String DEFAULT_SIGNATUREALGORITHM = "SHA1withRSA"; // Legacy default
    private static final long DEFAULT_BACKDATE = (long) 10 * 60; // 10 minutes in seconds
    private static final String SUBJECT_DUMMY = "L=_SignServer_DUMMY_CERT_";



    public OneTimeThread(final int id,
            final FailureCallback failureCallback,
            final String libName, final String libDir,
            final long slotId, final String pin,
            final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm,
            final Map<Long, Object> publicAttributesMap, final Map<Long, Object> privateAttributesMap) {
        super(failureCallback);
        this.id = id;
        this.failureCallback = failureCallback;
        this.libName = libName;
        this.libDir = libDir;
        this.slotId = slotId;
        this.pin = pin;
        this.warmupTime = warmupTime;
        this.timeLimit = timeLimit;
        this.useCache = useCache;
        this.signatureAlgorithm = signatureAlgorithm;
        this.publicAttributesMap = publicAttributesMap;
        this.privateAttributesMap = privateAttributesMap;
    }

    @Override
    public void run() {
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final JackNJI11Provider provider = slot.getProvider();

        slot.setUseCache(useCache);

        LOG.info("Starting thread " + id);

        final long startTime = System.currentTimeMillis();
        final long stopTime
                = timeLimit > 0 ? startTime + timeLimit : Long.MAX_VALUE;
        final long startCountingTime = startTime + warmupTime;
        long keyCounter = 0;

        try {
            while (!isStop()) {
                PrivateKey privKey = null;
                ++keyCounter;
                final String oneTimeKeyAlias = "onetime" + id + "-" + keyCounter;
                try {

                    final Map<String, Object> params = new HashMap<>(); // CLI currently does not support specifying Dummy certificate parameters as it is not required as of now

                    //TODO: Fix this
                    /*                    slot.generateKeyPair("RSA", "2048", oneTimeKeyAlias, false, publicAttributesMap, privateAttributesMap, new CryptokiDevice.CertificateGenerator() {
                        @Override
                        public X509Certificate generateCertificate(KeyPair keyPair, Provider provider) throws OperatorCreationException, CertificateException {
                            return createDummyCertificate(oneTimeKeyAlias, params, keyPair, slot.getProvider().getName());
                        }
                    }, true)*/;

                    privKey = slot.aquirePrivateKey(oneTimeKeyAlias);

                    // do simulated CSR signing & real signing 
                    for (int i = 0; i < 2; i++) {
                        String signingInput = "signing" + i;
                        doSign(privKey, signingInput, provider);
                    }

                    final long currTime = System.currentTimeMillis();

                    if (currTime > stopTime) {
                        break;
                    }

                    if (currTime >= startCountingTime) {
                        registerOperation();
                    }
                } finally {
                    if (privKey != null) {
                        slot.releasePrivateKey(privKey);
                    }
                    slot.removeKey(oneTimeKeyAlias);
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException
                | UnsupportedEncodingException | SignatureException
                | CryptoTokenOfflineException | RuntimeException e) {
            LOG.error("Failing signing: " + e.getMessage());
            fireFailure(getName() + ": failed after " + getNumberOfOperations() + " signings: " + e.getMessage());
        }
    }

    private void doSign(PrivateKey privKey, String inputData, JackNJI11Provider provider) throws InvalidKeyException, UnsupportedEncodingException, SignatureException, NoSuchAlgorithmException {
        final Signature sign = Signature.getInstance(signatureAlgorithm, provider);

        sign.initSign(privKey);
        sign.update(inputData.getBytes("UTF-8"));
        byte[] signature = sign.sign();

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signing in thread " + id);
            LOG.debug("Signature: " + new String(Base64.encode(signature)));
        }
    }
    
    
    /**
     * Create a dummy certificate with the provided parameters.
     * @param alias to use in the name
     * @param params map of parameters to use
     * @param keyPair where the public key will be in the certificate and the private used to sign it
     * @param provider for the keys
     * @return the new certificate
     * @throws OperatorCreationException
     * @throws CertificateException 
     */
    private static X509Certificate createDummyCertificate(final String alias, final Map<String, Object> params, final KeyPair keyPair, final String provider) throws OperatorCreationException, CertificateException {
        String dn = (String) params.get(PROPERTY_SELFSIGNED_DN);
        Long validity = (Long) params.get(PROPERTY_SELFSIGNED_VALIDITY);
        String signatureAlgorithm = (String) params.get(PROPERTY_SELFSIGNED_SIGNATUREALGORITHM);
        return createDummyCertificate(alias, dn, validity, signatureAlgorithm, keyPair, provider);
    }
    
    private static X509Certificate createDummyCertificate(final String alias, String dn, Long validity, String signatureAlgorithm, final KeyPair keyPair, final String provider) throws OperatorCreationException, CertificateException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Regenerate self signed certificate requested with values: "
                    + "DN: " + dn + ", "
                    + "validity: " + validity + ", "
                    + "signature algorithm: " + signatureAlgorithm);
        }
        // Our default DN
        if (dn == null) {
            dn = getDummyCertificateDN(alias);
        }

        // Our default validity
        if (validity == null) {
            validity = DEFAULT_VALIDITY_S;
        }

        // Our default signature algorithm
        if (signatureAlgorithm == null) {
            signatureAlgorithm = DEFAULT_SIGNATUREALGORITHM;
        }

        return getSelfCertificate(dn, DEFAULT_BACKDATE, validity, signatureAlgorithm, keyPair, provider);
    }
    
    private static String getDummyCertificateDN(String commonName) {
        return "CN=" + commonName + ", " + SUBJECT_DUMMY + ", C=SE";
    }
    
    
    private static X509Certificate getSelfCertificate(String myname, long backdate, long validity, String sigAlg, KeyPair keyPair, String provider)
            throws OperatorCreationException, CertificateException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - backdate * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);

        // Add all mandatory attributes
        if (LOG.isDebugEnabled()) {
            LOG.debug("keystore signing algorithm " + sigAlg);
        }

        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key is null");
        }

        X509v3CertificateBuilder cg = new JcaX509v3CertificateBuilder(new X500Principal(myname), BigInteger.valueOf(firstDate.getTime()), firstDate,
                lastDate, new X500Principal(myname), publicKey);
        final JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(sigAlg);
        contentSignerBuilder.setProvider(provider);

        final ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().getCertificate(cg.build(contentSigner));
    }
    
}
