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
package org.ejbca.core.ejb.keybind.impl;

import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyStoreBuilderParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.ExtendedKeyUsageConfiguration;
import org.cesecore.keys.token.BaseCryptoToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.p11.P11Slot;
import org.cesecore.util.CertTools;
import org.cesecore.util.provider.X509TrustManagerAcceptAll;
import org.ejbca.core.ejb.keybind.CertificateImportException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingBase;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;

/**
 * Used when this EJBCA instance authenticates to other instances.
 * 
 * @version $Id$
 */
public class ClientSSLKeyBinding extends InternalKeyBindingBase {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ClientSSLKeyBinding.class);

    public static final String IMPLEMENTATION_ALIAS = "ClientSSLKeyBinding"; // This should not change, even if we rename the class in EJBCA 5.3+..

    @SuppressWarnings("serial")
    public ClientSSLKeyBinding() {
        super(new ArrayList<InternalKeyBindingProperty<? extends Serializable>>() {{
        }});
    }

    @Override
    public String getImplementationAlias() {
        return IMPLEMENTATION_ALIAS;
    }

    @Override
    public float getLatestVersion() {
        return Long.valueOf(serialVersionUID).floatValue();
    }

    @Override
    public void assertCertificateCompatability(Certificate certificate) throws CertificateImportException {
        if (!(certificate instanceof X509Certificate)) {
            throw new CertificateImportException("Only X509 supported.");
        }
        try {
            final X509Certificate x509Certificate = (X509Certificate) certificate;
            log.debug("SubjectDN: " + CertTools.getSubjectDN(x509Certificate) + " IssuerDN: " + CertTools.getIssuerDN(x509Certificate));
            log.debug("Key usages: " + Arrays.toString(x509Certificate.getKeyUsage()));
            log.debug("Key usage (digitalSignature): " + x509Certificate.getKeyUsage()[0]);
            log.debug("Key usage (keyEncipherment): " + x509Certificate.getKeyUsage()[2]);
            for (String extendedKeyUsage : x509Certificate.getExtendedKeyUsage()) {
                log.debug("EKU: " + extendedKeyUsage + " (" +
                        ExtendedKeyUsageConfiguration.getExtendedKeyUsageOidsAndNames().get(extendedKeyUsage) + ")");
            }
            if (!x509Certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2")) {
                throw new CertificateImportException("Client SSL authentication EKU is required.");
            }
            if (!x509Certificate.getKeyUsage()[0]) {
                throw new CertificateImportException("Key usage digitalSignature is required.");
            }
            if (!x509Certificate.getKeyUsage()[2]) {
                throw new CertificateImportException("Key usage keyEncipherment is required.");
            }
        } catch (CertificateParsingException e) {
            throw new CertificateImportException(e);
        }
        log.warn("CERTIFICATE VALIDATION HAS NOT BEEN PORPERLY TESTED YET!");
    }

    @Override
    protected void upgrade(float latestVersion, float currentVersion) {
        // Nothing to do   
    }

    public SSLSocketFactory getAsSSLSocketFactory(CryptoToken cryptoToken, List<X509Certificate> chain, List<X509Certificate> trustedCertificates) {
        SSLSocketFactory sslSocketFactory = null;
        // TODO: This is very ugly.. we use reflection to access the underlying keystores and use them
        try {
            if (cryptoToken instanceof PKCS11CryptoToken) {
                final PKCS11CryptoToken p11CryptoToken = (PKCS11CryptoToken) cryptoToken;
                final Method methodGetP11Slot = PKCS11CryptoToken.class.getDeclaredMethod("getP11slot");
                methodGetP11Slot.setAccessible(true);
                final P11Slot p11Slot = (P11Slot) methodGetP11Slot.invoke(p11CryptoToken);
                final Provider provider = p11Slot.getProvider();
                // the application should already be logged in to the slot.
                final Builder p11builder = Builder.newInstance("PKCS11", provider, new KeyStore.CallbackHandlerProtection(new DoNothingCallbackHandler()));
                final KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
                final KeyStore keyStore = p11builder.getKeyStore();
                keyStore.load(null, null);
                setChainForRightAlias(cryptoToken, keyStore, chain);
                kmf.init(new KeyStoreBuilderParameters(p11builder));
                sslSocketFactory = getSSLSocketFactory(kmf, trustedCertificates);
            } else {
                BaseCryptoToken softCryptoToken = (BaseCryptoToken) cryptoToken;
                final Method methodGetKeyStore = BaseCryptoToken.class.getDeclaredMethod("getKeyStore");
                methodGetKeyStore.setAccessible(true);
                final KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
                final KeyStore keyStore = (KeyStore) methodGetKeyStore.invoke(softCryptoToken);
                setChainForRightAlias(cryptoToken, keyStore, chain);
                kmf.init(keyStore, null);
                sslSocketFactory = getSSLSocketFactory(kmf, trustedCertificates);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return sslSocketFactory;
    }
    
    private void setChainForRightAlias(CryptoToken cryptoToken, final KeyStore keyStore, List<X509Certificate> chain) throws Exception {
        final String keyPairAlias = getKeyPairAlias();
        final Enumeration<String> aliases = cryptoToken.getAliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final PublicKey currentPublicKey = cryptoToken.getPublicKey(keyPairAlias);
            final PrivateKey currentPrivateKey = cryptoToken.getPrivateKey(keyPairAlias);
            log.debug("keyStore.isKeyEntry(" + alias + ") " + keyStore.isKeyEntry(alias));
            log.debug("keyStore.isCertificateEntry(" + alias + ") " + keyStore.isCertificateEntry(alias));
            if (keyStore.isKeyEntry(alias)) {
                if (keyPairAlias.equals(alias)) {
                    // Install the provided chain for the alias to use..
                    keyStore.setKeyEntry(keyPairAlias, currentPrivateKey, null, chain.toArray(new X509Certificate[0]));
                    log.debug("Replaced certificate for " + keyPairAlias + " with chain certificate of size " + chain.size() +
                            ". Leaf Subject is " + CertTools.getSubjectDN(chain.get(0)));
                } else {
                    // ..and use dummy certificates with first available algorithm for all other keys in this slot
                    final X509Certificate dummyCertificate = CertTools.genSelfCert("CN=Dummy", 30*24*60*60*365, null, cryptoToken.getPrivateKey(getKeyPairAlias()),
                            currentPublicKey, AlgorithmTools.getSignatureAlgorithms(currentPublicKey).iterator().next(), false);
                    keyStore.setKeyEntry(keyPairAlias, cryptoToken.getPrivateKey(getKeyPairAlias()), null, new X509Certificate[] {dummyCertificate});
                    log.debug("Replaced certificate for " + keyPairAlias + " with dummy certificate.");
                }
            }
        }
    }

    /**
     * This callback handler is used for a p11 keystore that uses a slot which must already be in the login state.
     * If a callback is done anyway (this should never happen) an error is logged.
     */
    private class DoNothingCallbackHandler implements CallbackHandler {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            final StringBuilder sb = new StringBuilder("Callback handle not implemented for:\n");
            for (final Callback callback : callbacks) {
                sb.append("    Class ").append(callbacks.getClass().getCanonicalName()).append(" toString ").append(callback.toString());
            }
            log.error(sb.toString());
        }
    }

    private SSLSocketFactory getSSLSocketFactory(KeyManagerFactory kmf, List<X509Certificate> trustedCertificates) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyManagementException {
        // TODO: Create TrustManager from trusted certs
        final TrustManager trustManagers[];
        if (trustedCertificates == null || trustedCertificates.isEmpty()) {
            trustManagers = new X509TrustManager[] {new X509TrustManagerAcceptAll()};
        } else {
            throw new RuntimeException("Configurable trust not yet implemented.");
        }
        // Now construct a SSLContext using these (possibly wrapped) KeyManagers, and the TrustManagers.
        // We still use a null SecureRandom, indicating that the defaults should be used.
        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), trustManagers, null);
        // Finally, we get a SocketFactory, and pass it on.
        return  context.getSocketFactory();
    }
}
