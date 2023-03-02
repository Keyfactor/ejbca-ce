/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyGenerator;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.KeyGenParams;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

/**
 * 
 */
public class KeyStoreTools {
    private static final Logger log = Logger.getLogger(KeyStoreTools.class);

    protected final CachingKeyStoreWrapper keyStore;
    private final String providerName;

    public KeyStoreTools(CachingKeyStoreWrapper keyStore, String providerName){
        this.keyStore = keyStore;
        this.providerName = providerName;
    }

    /**
     * @return the name of the Provider used by this container
     */
    public String getProviderName() {
        return this.providerName;
    }

    /**
     * @return a reference to the KeyStore for this container
     */
    public CachingKeyStoreWrapper getKeyStore() {
        return this.keyStore;
    }

    public void setKeyEntry(String alias, Key key, Certificate[] chain) throws KeyStoreException {
        // Removal of old key is only needed for sun-p11 with none ASCII chars in the alias.
        // But it makes no harm to always do it and it should be fast.
        // If not done the entry will not be stored correctly in the p11 KeyStore.
        getKeyStore().deleteEntry(alias);
        getKeyStore().setKeyEntry(alias, key, null, chain);
    }

    private void deleteAlias(String alias) throws KeyStoreException {
        getKeyStore().deleteEntry(alias);
    }
    /** Deletes an entry in the keystore
     *
     * @param alias is a reference to the entry in the KeyStore that should be deleted, if alias is null, all entries are deleted.
     * @throws KeyStoreException  key store exception.
     */
    public void deleteEntry(final String alias) throws KeyStoreException {
        if ( alias!=null ) {
            deleteAlias(alias);
            return;
        }
        final Enumeration<String> e = getKeyStore().aliases();
        while( e.hasMoreElements() ) {
            final String str = e.nextElement();
            deleteAlias( str );
        }
    }
    /**
     * Rename the alias of an entry.
     * This has just been tested on pkcs#11 keystores. On other keystore it might
     * be that you will get two aliases for the same key (copy). But on p11
     * we know that the oldAlias is not existing after the method is called.
     *
     * @param oldAlias is the current name
     * @param newAlias is the new name
     */
    public void renameEntry( String oldAlias, String newAlias ) {
        // only one key with same public part (certificate) is existing on a p11 token. this has been tested.
        try {
            getKeyStore().setEntry(newAlias, getKeyStore().getEntry(oldAlias, null), null);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new KeyUtilRuntimeException("Renaming entry failed.", e);
        }
    }

    private static class CertificateSignOperation implements ISignOperation {

        private final PrivateKey privateKey;
        private final X509v3CertificateBuilder certificateBuilder;
        private X509CertificateHolder result;

        public CertificateSignOperation(
                final PrivateKey pk,
                final X509v3CertificateBuilder cb) {
            this.privateKey = pk;
            this.certificateBuilder = cb;
        }
        @SuppressWarnings("synthetic-access")
        @Override
        public void taskWithSigning(String sigAlg, Provider provider) throws TaskWithSigningException {
            log.debug("Keystore signing algorithm " + sigAlg);
            final ContentSigner signer;
            try {
                signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(provider.getName()).build(this.privateKey), 20480);
            } catch (OperatorCreationException e) {
                throw new TaskWithSigningException(String.format("Signing certificate failed: %s", e.getMessage()), e);
            }
            this.result = this.certificateBuilder.build(signer);
        }
        public X509CertificateHolder getResult() {
            return this.result;
        }
    }

    private X509Certificate getSelfCertificate(String myName, long validity, List<String> sigAlgs, KeyPair keyPair) throws InvalidKeyException,
            CertificateException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        final X500Name issuer = new X500Name(myName);
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());
        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new InvalidKeyException("Public key is null");
        }

        try {
            final X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(issuer, serno, firstDate, lastDate, issuer, publicKey);
            final CertificateSignOperation cso = new CertificateSignOperation(keyPair.getPrivate(), cb);
            String provider = this.providerName;
            if (BouncyCastleProvider.PROVIDER_NAME.equals(this.providerName)) {
                provider = CryptoProviderTools.getProviderNameFromAlg(sigAlgs.get(0));
            }
            SignWithWorkingAlgorithm.doSignTask(sigAlgs, provider, cso);
            final X509CertificateHolder cert = cso.getResult();
            if ( cert==null ) {
                throw new CertificateException("Self signing of certificate failed.");
            }
            return CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
        } catch (TaskWithSigningException e) {
            log.error("Error creating content signer: ", e);
            throw new CertificateException(e);
        } catch (IOException e) {
            throw new CertificateException("Could not read certificate", e);
        } catch (NoSuchProviderException e) {
            throw new CertificateException(String.format("Provider '%s' does not exist.", this.providerName), e);
        }
    }

    private void generateEC(final String ecNamedCurveBc, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate EC: curve name "+ecNamedCurveBc+", keyEntryName "+keyAlias);
        }
        if (StringUtils.contains(Security.getProvider(this.providerName).getClass().getName(), "iaik")) {
            throw new InvalidAlgorithmParameterException("IAIK ECC key generation not implemented.");
        }
        final AlgorithmParameterSpec keyParams;

        // Convert it to the OID if possible since the human friendly name might differ in the provider
        if (ECUtil.getNamedCurveOid(ecNamedCurveBc) != null) {
            final String oidOrName = AlgorithmTools.getEcKeySpecOidFromBcName(ecNamedCurveBc);
            if (log.isDebugEnabled()) {
                log.debug("keySpecification '" + ecNamedCurveBc + "' transformed into OID " + oidOrName);
            }
            keyParams = new ECGenParameterSpec(oidOrName);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Curve did not have an OID in BC, trying to pick up Parameter spec: " + ecNamedCurveBc);
            }
            // This may be a new curve without OID, like curve25519 and we have to do something a bit different
            X9ECParameters ecP = CustomNamedCurves.getByName(ecNamedCurveBc);
            if (ecP == null) {
                throw new InvalidAlgorithmParameterException("Can not generate EC curve, no OID and no ECParameters found: " + ecNamedCurveBc);
            }
            keyParams = new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }
        
     
        generateKeyPair(keyParams, keyAlias, AlgorithmConstants.KEYALGORITHM_EC, AlgorithmTools.SIG_ALGS_ECDSA);
        
        if (log.isTraceEnabled()) {
            log.trace("<generate: curve name "+ecNamedCurveBc+", keyEntryName "+keyAlias);
        }
    }

    private void generateExtraEC(
            final String name, final String keyAlias, final String keyAlgorithm,
            final List<String> sigAlgNames) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate "+keyAlgorithm+": curve name "+name+", keyEntryName "+keyAlias);
        }
        // Generate the EC Keypair
        final ECGenParameterSpec keyParams = new ECGenParameterSpec(name);
        generateKeyPair(keyParams, keyAlias, keyAlgorithm, sigAlgNames);
        
        if (log.isTraceEnabled()) {
            log.trace("<generate: curve name "+name+", keyEntryName "+keyAlias);
        }
    }

    private void generateGOST3410(final String name, final String keyEntryName) throws
            InvalidAlgorithmParameterException {
        generateExtraEC(
                name, keyEntryName, AlgorithmConstants.KEYALGORITHM_ECGOST3410,
                AlgorithmTools.SIG_ALGS_ECGOST3410);
    }

    private void generateDSTU4145(final String name, final String keyEntryName) throws
            InvalidAlgorithmParameterException {
        generateExtraEC(
                name, keyEntryName, AlgorithmConstants.KEYALGORITHM_DSTU4145,
                AlgorithmTools.SIG_ALGS_DSTU4145);
    }

    private void generateRSA(final int keySize, final String keyEntryName) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
        generateKeyPair(
                new SizeAlgorithmParameterSpec(keySize), keyEntryName,
                AlgorithmConstants.KEYALGORITHM_RSA,
                AlgorithmTools.SIG_ALGS_RSA_NOSHA1);
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
    }

    private void generateDSA(final int keySize, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySize " + keySize + ", keyEntryName " + keyAlias);
        }
        // Generate the DSA Keypair
        generateKeyPair(
                new SizeAlgorithmParameterSpec(keySize), keyAlias,
                AlgorithmConstants.KEYALGORITHM_DSA, AlgorithmTools.SIG_ALGS_DSA);
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyAlias);
        }
    }

    private void generateEdDSAOrPQC(final String keySpec, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySpec " + keySpec+ ", keyEntryName " + keyAlias);
        }
        // Generate the Keypair
        final List<String> sigAlgs;
        switch (keySpec) {
        case AlgorithmConstants.KEYALGORITHM_ED25519:
            sigAlgs = AlgorithmTools.SIG_ALGS_ED25519;
            break;
        case AlgorithmConstants.KEYALGORITHM_ED448:
            sigAlgs = AlgorithmTools.SIG_ALGS_ED448;
            break;
        case AlgorithmConstants.KEYALGORITHM_FALCON512:
            sigAlgs = AlgorithmTools.SIG_ALGS_FALCON512;
            break;
        case AlgorithmConstants.KEYALGORITHM_FALCON1024:
            sigAlgs = AlgorithmTools.SIG_ALGS_FALCON1024;
            break;
        case AlgorithmConstants.KEYALGORITHM_DILITHIUM2:
            sigAlgs = AlgorithmTools.SIG_ALGS_DILITHIUM2;
            break;
        case AlgorithmConstants.KEYALGORITHM_DILITHIUM3:
            sigAlgs = AlgorithmTools.SIG_ALGS_DILITHIUM3;
            break;
        case AlgorithmConstants.KEYALGORITHM_DILITHIUM5:
            sigAlgs = AlgorithmTools.SIG_ALGS_DILITHIUM5;
            break;
        default:
            throw new InvalidAlgorithmParameterException("Only Ed25519, Ed448, FALCON-512, FALCON-1024, DILITHIUM2, DILITHIUM3, DILITHIUM5 is allowed for EdDSA/PQC key generation: " + keySpec);
        }
        generateKeyPair(null, keyAlias, keySpec, sigAlgs);
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySpec " + keySpec + ", keyEntryName " + keyAlias);
        }
    }

    /** Generates asymmetric keys in the Keystore token.
     *
     * @param keySpec all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param keyEntryName key entry name.
     */
    public void generateKeyPair(final String keySpec, final String keyEntryName) throws
            InvalidAlgorithmParameterException {
        if (keySpec.toUpperCase().startsWith("ED") || keySpec.toUpperCase().startsWith("FALCON") || keySpec.toUpperCase().startsWith("DILITHIUM")) {
            generateEdDSAOrPQC(keySpec, keyEntryName);
        } else if (keySpec.toUpperCase().startsWith("DSA")) {
            generateDSA(Integer.parseInt(keySpec.substring(3).trim()), keyEntryName);
        } else if (AlgorithmConfigurationCache.INSTANCE.isGost3410Enabled() && keySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
            generateGOST3410(keySpec, keyEntryName);
        } else if (AlgorithmConfigurationCache.INSTANCE.isDstu4145Enabled() && keySpec.startsWith(AlgorithmConstants.DSTU4145_OID + ".")) {
            generateDSTU4145(keySpec, keyEntryName);
        } else {
            final String formatCheckedKeySpec = KeyGenParams.getKeySpecificationNumeric(keySpec);
            try {
                generateRSA(Integer.parseInt(formatCheckedKeySpec.trim()), keyEntryName);
            } catch (NumberFormatException e) {
                generateEC(keySpec, keyEntryName);
            }
        }
    }

    /** Generates symmetric keys in the Keystore token.
     *
     * @param algorithm symmetric algorithm specified in http://download.oracle.com/javase/1.5.0/docs/api/index.html, suggest AES, DESede or DES
     * @param keysize keysize of symmetric key, suggest 128 or 256 for AES, 64 for 168 for DESede and 64 for DES
     * @param keyEntryName the alias the key will get in the keystore
     * @throws NoSuchProviderException provider exception.
     * @throws NoSuchAlgorithmException algorithm exception.
     * @throws KeyStoreException  key store exception.
     */
    public void generateKey(final String algorithm, final int keysize,
                            final String keyEntryName) throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException {
        final KeyGenerator generator = KeyGenerator.getInstance(algorithm, this.providerName);
        generator.init(keysize);
        final Key key = generator.generateKey();
        setKeyEntry(keyEntryName, key, null);
    }

    /** Generates keys in the Keystore token.
     * @param keyParams AlgorithmParameterSpec for the KeyPairGenerator. Can be anything like RSAKeyGenParameterSpec, DSAParameterSpec, ECParameterSpec or ECGenParameterSpec.
     * @param keyAlias key alias.
     * @throws InvalidAlgorithmParameterException invalid algorithm parameter exception.
     */
    public void generateKeyPair(final AlgorithmParameterSpec keyParams, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate from AlgorithmParameterSpec: "+keyParams.getClass().getName());
        }
        // Generate the KeyPair
        final String keyAlgorithm;
        final List<String> certSignAlgorithms;
        final String specName = keyParams.getClass().getName();
        if (specName.equals(EdDSAParameterSpec.class.getName())) {
            EdDSAParameterSpec edSpec = (EdDSAParameterSpec) keyParams;
            keyAlgorithm = edSpec.getCurveName();
            certSignAlgorithms = Collections.singletonList(edSpec.getCurveName());
        } else if (specName.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DSA;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_DSA;
        } else if (specName.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_RSA_NOSHA1;
        } else if (specName.equals(FalconParameterSpec.class.getName())) {
            if (FalconParameterSpec.falcon_512.equals(keyParams)) {
                keyAlgorithm = AlgorithmConstants.KEYALGORITHM_FALCON512;
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_FALCON512;
            } else if (FalconParameterSpec.falcon_1024.equals(keyParams)) {
                keyAlgorithm = AlgorithmConstants.KEYALGORITHM_FALCON1024;
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_FALCON1024;
            } else {
                throw new InvalidAlgorithmParameterException("Invalid Falcon keyspec: " + keyParams.toString());
            }
        } else if (specName.equals(DilithiumParameterSpec.class.getName())) {
            if (DilithiumParameterSpec.dilithium2.equals(keyParams)) {
                keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DILITHIUM2;
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_DILITHIUM2;
            } else if (DilithiumParameterSpec.dilithium3.equals(keyParams)) {
                keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DILITHIUM3;
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_DILITHIUM3;
            } else if (DilithiumParameterSpec.dilithium5.equals(keyParams)) {
                keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DILITHIUM5;
                certSignAlgorithms = AlgorithmTools.SIG_ALGS_DILITHIUM5;
            } else {
                throw new InvalidAlgorithmParameterException("Invalid Dilithium keyspec: " + keyParams.toString());
            }
        } else {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_EC;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_ECDSA;
        }
        generateKeyPair(keyParams, keyAlias, keyAlgorithm, certSignAlgorithms);
    }

    private static class SizeAlgorithmParameterSpec implements AlgorithmParameterSpec {
        final int keySize;
        public SizeAlgorithmParameterSpec(final int keySize) {
            this.keySize = keySize;
        }
    }

    private void generateKeyPair(final AlgorithmParameterSpec keyParams, final String keyAlias, final String keyAlgorithm,
            final List<String> certSignAlgorithms) throws InvalidAlgorithmParameterException {
        final KeyPairGenerator kpg;
        try {
            String provider = this.providerName;
            if (BouncyCastleProvider.PROVIDER_NAME.equals(this.providerName)) {
                provider = CryptoProviderTools.getProviderNameFromAlg(keyAlgorithm);
            }
            kpg = KeyPairGenerator.getInstance(keyAlgorithm, provider);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + keyAlgorithm + " was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException(this.providerName+ " was not found as a provider.", e);
        }

        try {
            if (keyParams instanceof SizeAlgorithmParameterSpec) {
                kpg.initialize(((SizeAlgorithmParameterSpec) keyParams).keySize);
            } else if (keyParams != null || keyAlgorithm.startsWith("EC")) {
                // Null here means "implicitlyCA", which is allowed only for EC keys
                kpg.initialize(keyParams);
            }
        } catch (InvalidAlgorithmParameterException e) {
            log.debug("Algorithm parameters not supported: " + e.getMessage());
            throw e;
        }
    
        // We will make a loop to retry key generation here. Using the IAIK provider it seems to give
        // CKR_OBJECT_HANDLE_INVALID about every second time we try to store keys
        // But if we try again it succeeds
        int bar = 0;
        while (bar < 3) {
            try {
                log.debug("generating...");
                final KeyPair keyPair = kpg.generateKeyPair();
                final X509Certificate selfSignedCert = getSelfCertificate("CN=Dummy certificate created by a CESeCore application", (long) 30 * 24 * 60 * 60 * 365, certSignAlgorithms, keyPair);
                final X509Certificate chain[] = new X509Certificate[]{selfSignedCert};
                if (log.isDebugEnabled()) {
                    log.debug("Creating certificate with entry " + keyAlias + '.');
                }
                setKeyEntry(keyAlias, keyPair.getPrivate(), chain);
                break; // success no need to try more
            } catch (KeyStoreException e) {
                if ( bar<3 ) {
                    log.info("Failed to generate or store new key, will try 3 times. This was try: " + bar, e);
                } else {
                    throw new KeyCreationException("Signing failed.", e);
                }
            } catch(CertificateException e) {
                throw new KeyCreationException("Can't create keystore because dummy certificate chain creation failed.",e);
            } catch (InvalidKeyException e) {
               throw new KeyCreationException("Dummy certificate chain was created with an invalid key" , e);
            }
            bar++;
        }
        if (log.isTraceEnabled()) {
            log.trace("<generate from AlgorithmParameterSpec: "+(keyParams!=null ? keyParams.getClass().getName() : "null"));
        }
    }

    private class SignCsrOperation implements ISignOperation {
        final private String alias;
        final private String sDN;
        final private boolean explicitEccParameters;
        final private PublicKey publicKeyTmp;
        private PKCS10CertificationRequest certReq;

        public SignCsrOperation(final String _alias, final String _sDN, final boolean _explicitEccParameters, final PublicKey publicKey) {
            this.alias = _alias;
            this.sDN = _sDN;
            this.explicitEccParameters = _explicitEccParameters;
            this.certReq = null;
            this.publicKeyTmp = publicKey;
        }
        @SuppressWarnings("synthetic-access")
        private void signCSR(final String signAlgorithm, final Provider provider) throws NoSuchAlgorithmException, NoSuchProviderException, UnrecoverableKeyException, KeyStoreException, OperatorCreationException, TaskWithSigningException {
            final PublicKey publicKey;
            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "alias: %s SHA1 of public key: %s",
                        this.alias,
                        CertTools.getFingerprintAsString(this.publicKeyTmp.getEncoded())
                        ));
            }
            if (signAlgorithm.contains("ECDSA") && this.explicitEccParameters) {
                log.info("Using explicit parameter encoding for ECC key.");
                publicKey = ECKeyUtil.publicToExplicitParameters(this.publicKeyTmp, "BC");
            } else {
                log.info("Using named curve parameter encoding for ECC key.");
                publicKey = this.publicKeyTmp;
            }
            final PrivateKey privateKey = getPrivateKey(this.alias);
            final X500Name sDNName = this.sDN!=null ? new X500Name(this.sDN) : new X500Name("CN="+this.alias);
            this.certReq = CertTools.genPKCS10CertificationRequest(
                    signAlgorithm,
                    sDNName,
                    publicKey, new DERSet(),
                    privateKey,
                    provider.getName() );
            if ( this.certReq==null) {
                throw new TaskWithSigningException("Not possible to sign CSR.");
            }
        }
        @Override
        public void taskWithSigning(final String signAlgorithm, final Provider provider) throws TaskWithSigningException {
            try {
                signCSR(signAlgorithm, provider);
            } catch (OperatorCreationException | UnrecoverableKeyException | NoSuchAlgorithmException | NoSuchProviderException | KeyStoreException e) {
                throw new TaskWithSigningException(String.format("Not possible to sign CSR: %s", e.getMessage()), e);
            }
        }
        public PKCS10CertificationRequest getResult() {
            return this.certReq;
        }
    }
    /** Generates a certificate request (CSR) in PKCS#10 format and writes to file
     * @param alias for the key to be used
     * @param sDN the DN to be used. If null the 'CN=alias' will be used
     * @param explicitEccParameters false should be default and will use NamedCurve encoding of ECC public keys (IETF recommendation), use true to include all parameters explicitly (ICAO ePassport requirement).
     */
    public void generateCertReq(String alias, String sDN, boolean explicitEccParameters) {
        try {
            final PublicKey publicKey = getCertificate(alias).getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug("alias: " + alias + " SHA1 of public key: " + CertTools.getFingerprintAsString(publicKey.getEncoded()));
            }
            // Candidate algorithms. The first working one will be selected by SignWithWorkingAlgorithm
            final List<String> sigAlg = AlgorithmTools.getSignatureAlgorithms(publicKey);
            final SignCsrOperation operation = new SignCsrOperation(alias, sDN, explicitEccParameters, publicKey);
            SignWithWorkingAlgorithm.doSignTask(sigAlg, this.providerName, operation);
            final PKCS10CertificationRequest certReq = operation.getResult();
            final ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(publicKey);
            if ( !certReq.isSignatureValid(verifier) ) {
                final String msg = "Certificate request is not verifying.";
                throw new KeyUtilRuntimeException(msg);
            }
            final String filename = alias+".pem";

            try( final OutputStream os = new FileOutputStream(filename) ) {
                os.write( CertTools.getPEMFromCertificateRequest(certReq.getEncoded()) );
            }
            log.info("Wrote csr to file: "+filename);
        } catch (KeyStoreException | NoSuchProviderException | TaskWithSigningException | OperatorCreationException | PKCSException | IOException  e) {
            throw new KeyUtilRuntimeException("Failed to generate a certificate request.", e);
        }
    }

    /**
     * Install certificate chain to key in keystore.
     * @param fileName name of the file with chain. Starting with the certificate of the key. Ending with the root certificate.
     */
    public void installCertificate(final String fileName) {
        try( final InputStream is = new FileInputStream(fileName) ) {
            final X509Certificate[] chain;
            chain = CertTools.getCertsFromPEM(is, X509Certificate.class).toArray(new X509Certificate[0]);
            final PublicKey importPublicKey = chain[0].getPublicKey();
            final String importKeyHash = CertTools.getFingerprintAsString(importPublicKey.getEncoded());
            final Enumeration<String> eAlias = getKeyStore().aliases();
            boolean notFound = true;
            while ( eAlias.hasMoreElements() && notFound ) {
                final String alias = eAlias.nextElement();
                final PublicKey hsmPublicKey = getCertificate(alias).getPublicKey();
                if (log.isDebugEnabled()) {
                    log.debug("alias: " + alias + " SHA1 of public hsm key: " + CertTools.getFingerprintAsString(hsmPublicKey.getEncoded())
                    + " SHA1 of first public key in chain: " + importKeyHash
                    +  (chain.length==1?"":("SHA1 of last public key in chain: " + CertTools.getFingerprintAsString(chain[chain.length-1].getPublicKey().getEncoded()))));
                }
                if ( hsmPublicKey.equals(importPublicKey) ) {
                    log.info("Found a matching public key for alias \"" + alias + "\".");
                    getKeyStore().setKeyEntry(alias, getPrivateKey(alias), null, chain);
                    notFound = false;
                }
            }
            if ( notFound ) {
                final String msg = "Key with public key hash " + importKeyHash + " not on token.";
                throw new KeyUtilRuntimeException(msg);
            }
        } catch (IOException | CertificateParsingException | KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new KeyUtilRuntimeException("Failed to install cert chain into keystore.", e);
        }
    }

    /**
     * Install trusted root in trust store
     * @param fileName name of the trusted root.
     */
    public void installTrustedRoot(String fileName) {
        try( final InputStream is = new FileInputStream(fileName) ) {
            final List<Certificate> chain = CertTools.getCertsFromPEM(is, Certificate.class);
            if ( chain.size()<1 ) {
                throw new KeyUtilRuntimeException("No certificate in file");
            }
            // assume last cert in chain is root if more than 1
            getKeyStore().setCertificateEntry("trusted", chain.get(chain.size()-1));
        } catch (IOException | CertificateParsingException | KeyStoreException e) {
            throw new KeyUtilRuntimeException("Failing to install trusted certificate.", e);
        }
    }
    private PrivateKey getPrivateKey(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        final PrivateKey key = (PrivateKey)getKey(alias);
        if ( key==null ) {
            String msg = "Key alias '" + alias + "' not found in keystore.";
            log.info(msg);
        }
        return key;
    }
    private Key getKey(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return getKeyStore().getKey(alias, null);
    }
    private X509Certificate getCertificate( String alias ) throws KeyStoreException {
        final X509Certificate cert = (X509Certificate)this.keyStore.getCertificate(alias);
        if ( cert==null ) {
            String msg = "Certificate alias '" + alias +"' not found in keystore."; 
            log.info(msg);
        }
        return cert;
    }

    /**
     * Encodes a Keystore to a byte array.
     * @param keyStore the keystore.
     * @param password the password.
     * @return the keystore encoded as byte array.
     */
    public static byte[] getAsByteArray(final KeyStore keyStore, final String password) {
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            keyStore.store(outputStream, password.toCharArray());
            return outputStream.toByteArray();
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error(e); //should never happen if keyStore is valid object
        }
        return null;
    }
}
