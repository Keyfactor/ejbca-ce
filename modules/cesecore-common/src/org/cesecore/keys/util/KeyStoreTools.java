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
package org.cesecore.keys.util;

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
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.KeyGenerator;

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
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.KeyCreationException;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.keys.token.p11.PKCS11Utils;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 */
public class KeyStoreTools {
    private static final Logger log = Logger.getLogger(KeyStoreTools.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    protected final CachingKeyStoreWrapper keyStore;
    private final String providerName;

    public KeyStoreTools(CachingKeyStoreWrapper _keyStore, String _providerName){
        this.keyStore = _keyStore;
        this.providerName = _providerName;
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

    public void setKeyEntry(String alias, Key key, Certificate chain[]) throws KeyStoreException {
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
     * @return keystore identifier
     * 
     * @throws KeyStoreException 
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

    private class CertificateSignOperation implements ISignOperation {

        final private PrivateKey privateKey;
        final private X509v3CertificateBuilder certificateBuilder;
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
    private X509Certificate getSelfCertificate(String myname, long validity, List<String> sigAlgs, KeyPair keyPair) throws InvalidKeyException,
            CertificateException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        final X500Name issuer = new X500Name(myname);
        final BigInteger serno = BigInteger.valueOf(firstDate.getTime());
        final PublicKey publicKey = keyPair.getPublic();
        if (publicKey == null) {
            throw new InvalidKeyException("Public key is null");
        }

        try {
            final X509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(issuer, serno, firstDate, lastDate, issuer, publicKey);
            final CertificateSignOperation cso = new CertificateSignOperation(keyPair.getPrivate(), cb);
            SignWithWorkingAlgorithm.doSignTask(sigAlgs, this.providerName, cso);
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
        if (StringUtils.equals(ecNamedCurveBc,"implicitlyCA")) {
            if (log.isDebugEnabled()) {
                log.debug("Generating implicitlyCA encoded ECDSA key pair");
            }
            // If the keySpec is null, we have "implicitlyCA" defined EC parameters
            // The parameters were already installed when we installed the provider
            // We just make sure that ecSpec == null here
            keyParams = null;
        } else {
            // Convert it to the OID if possible since the human friendly name might differ in the provider
            if (ECUtil.getNamedCurveOid(ecNamedCurveBc) != null) {
                final String oidOrName = AlgorithmTools.getEcKeySpecOidFromBcName(ecNamedCurveBc);
                if (log.isDebugEnabled()) {
                    log.debug("keySpecification '"+ecNamedCurveBc+"' transformed into OID " + oidOrName);
                }
                keyParams = new ECGenParameterSpec(oidOrName);
            } else {
                log.debug("Curve did not have an OID in BC, trying to pick up Parameter spec: " + ecNamedCurveBc);
                // This may be a new curve without OID, like curve25519 and we have to do something a bit different
                X9ECParameters ecP = CustomNamedCurves.getByName(ecNamedCurveBc);
                if (ecP == null) {
                    throw new InvalidAlgorithmParameterException("Can not generate EC curve, no OID and no ECParameters found: "+ecNamedCurveBc);
                }
                keyParams = new org.bouncycastle.jce.spec.ECParameterSpec(
                        ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed()); 
            }
        }
        try {
            generateKeyPair(
                    keyParams, keyAlias,
                    AlgorithmConstants.KEYALGORITHM_EC,
                    AlgorithmTools.SIG_ALGS_ECDSA);
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC name "+ecNamedCurveBc+" not supported.");
            throw e;
        }
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
        try {
            generateKeyPair(keyParams, keyAlias, keyAlgorithm, sigAlgNames);
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC "+keyAlgorithm+" name "+name+" not supported.");
            throw e;
        }
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
                AlgorithmTools.SIG_ALGS_RSA);
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
    }

    private void generateDSA(final int keySize, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySize " + keySize + ", keyEntryName " + keyAlias);
        }
        // Generate the RSA Keypair
        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("DSA", this.providerName);
        } catch (NoSuchAlgorithmException e) {
           throw new IllegalStateException("Algorithm " + "DSA" + " was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        kpg.initialize(keySize);
        generateKeyPair(
                new SizeAlgorithmParameterSpec(keySize), keyAlias,
                AlgorithmConstants.KEYALGORITHM_DSA, AlgorithmTools.SIG_ALGS_DSA);
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyAlias);
        }
    }

    /** Generates asymmteric keys in the Keystore token.
     * 
     * @param keySpec all decimal digits RSA key length, otherwise name of ECC curve or DSA key using syntax DSAnnnn
     * @param keyEntryName
     */
    public void generateKeyPair(final String keySpec, final String keyEntryName) throws
            InvalidAlgorithmParameterException {

        if (keySpec.toUpperCase().startsWith("DSA")) {
            generateDSA(Integer.parseInt(keySpec.substring(3).trim()), keyEntryName);
        } else if (AlgorithmTools.isGost3410Enabled() && keySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
            generateGOST3410(keySpec, keyEntryName);
        } else if (AlgorithmTools.isDstu4145Enabled() && keySpec.startsWith(CesecoreConfiguration.getOidDstu4145() + ".")) {
            generateDSTU4145(keySpec, keyEntryName);
        } else {

            try {
                generateRSA(Integer.parseInt(keySpec.trim()), keyEntryName);
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
     * @throws NoSuchProviderException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
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
     * @param keyAlias
     * @throws InvalidAlgorithmParameterException 
     */
    public void generateKeyPair(final AlgorithmParameterSpec keyParams, final String keyAlias) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
            log.trace(">generate from AlgorithmParameterSpec: "+keyParams.getClass().getName());
        }
        // Generate the Keypair
        final String keyAlgorithm;
        final List<String> certSignAlgorithms;
        final String specName = keyParams.getClass().getName();
        if (specName.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DSA;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_DSA;
        } else if (specName.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_RSA;
        } else {
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_EC;
            certSignAlgorithms = AlgorithmTools.SIG_ALGS_ECDSA;
        }
        generateKeyPair(keyParams, keyAlias, keyAlgorithm, certSignAlgorithms);
    }
    private class SizeAlgorithmParameterSpec implements AlgorithmParameterSpec {
        final int keySize;
        public SizeAlgorithmParameterSpec(final int _keySize) {
            this.keySize = _keySize;
        }
    }
    private void generateKeyPair(
            final AlgorithmParameterSpec keyParams, final String keyAlias,
            final String keyAlgorithm,
            final List<String> certSignAlgorithms) throws InvalidAlgorithmParameterException {
        final KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(keyAlgorithm, this.providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + keyAlgorithm + " was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        try {
            if ( keyParams instanceof SizeAlgorithmParameterSpec ) {
                kpg.initialize(((SizeAlgorithmParameterSpec)keyParams).keySize);
            } else {
                kpg.initialize(keyParams);
            }
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("Algorithm parameters not supported: "+e.getMessage());
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
                log.debug("Creating certificate with entry " + keyAlias + '.');
                setKeyEntry(keyAlias, keyPair.getPrivate(), chain);
                if ( CesecoreConfiguration.makeKeyUnmodifiableAfterGeneration() ) {
                    PKCS11Utils.getInstance().makeKeyUnmodifiable(keyPair.getPrivate(), this.providerName);
                }
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
            } catch (TaskWithSigningException e) {
                throw e;
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
                final String msg = intres.getLocalizedMessage("token.errorcertreqverify", alias);
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
     * @param file name of the file with chain. Starting with the certificate of the key. Ending with the root certificate.
     */
    public void installCertificate(final String fileName) {
        try( final InputStream is = new FileInputStream(fileName) ) {
            final X509Certificate chain[];
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
                final String msg = intres.getLocalizedMessage("token.errorkeynottoken", importKeyHash);
                throw new KeyUtilRuntimeException(msg);
            }
        } catch (IOException | CertificateParsingException | KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            throw new KeyUtilRuntimeException("Failed to install cert chain into keystore.", e);
        }
    }
    
    /**
     * Install trusted root in trust store
     * @param File name of the trusted root.
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
            String msg = intres.getLocalizedMessage("token.errornokeyalias", alias);
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
            String msg = intres.getLocalizedMessage("token.errornocertalias", alias);
            log.info(msg);
        }
        return cert;
    }

}
