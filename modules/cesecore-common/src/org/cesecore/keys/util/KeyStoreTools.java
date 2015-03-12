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
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.KeyCreationException;
import org.cesecore.keys.token.CachingKeyStoreWrapper;
import org.cesecore.util.Base64;
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
     * @throws IOException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException 
     */
    public void deleteEntry(final String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if ( alias!=null ) {
            deleteAlias(alias);
        } else {
            Enumeration<String> e = getKeyStore().aliases();
            while( e.hasMoreElements() ) {
            	final String str = e.nextElement();
                deleteAlias( str );
            }
        }
    }
    /**
     * Creates a new entry identical with another entry.
     *  
     * @param oldAlias is the current name
     * @param newAlias is the new name
     * @return keystore identifier
     * @throws UnrecoverableEntryException 
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws IOException 
     * @throws CertificateException 
     */
    public void copyEntry( String oldAlias, String newAlias ) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException, IOException {
    	getKeyStore().setEntry(newAlias, getKeyStore().getEntry(oldAlias, null), null);
    }

    private X509Certificate getSelfCertificate(String myname, long validity, String sigAlg, KeyPair keyPair) throws InvalidKeyException,
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
            final X509v3CertificateBuilder cg = new JcaX509v3CertificateBuilder(issuer, serno, firstDate, lastDate, issuer, publicKey);
            log.debug("Keystore signing algorithm " + sigAlg);
            final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(this.providerName).build(keyPair.getPrivate()), 20480);
            final X509CertificateHolder cert = cg.build(signer);
            return (X509Certificate) CertTools.getCertfromByteArray(cert.getEncoded());
        } catch (OperatorCreationException e) {
            log.error("Error creating content signer: ", e);
            throw new CertificateException(e);
        } catch (IOException e) {
            throw new CertificateException("Could not read certificate", e);
        }
    }

    private void generateEC(final String name, final String keyEntryName) throws InvalidAlgorithmParameterException {
        if (log.isTraceEnabled()) {
        	log.trace(">generate EC: curve name "+name+", keyEntryName "+keyEntryName);
        }
        // Generate the EC Keypair
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("EC", this.providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + "EC" + "was not recognized.", e);
         } catch (NoSuchProviderException e) {
             throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
         }
        try {
			Provider prov = Security.getProvider(this.providerName);
			if (StringUtils.contains(prov.getClass().getName(), "iaik")) {
        		throw new InvalidAlgorithmParameterException("IAIK ECC key generation not implemented.");
        		/*
        		ECDSAPrivateKey privateKeyTemplate = new ECDSAPrivateKey();
        		privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        		privateKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);

        		ECDSAPublicKey publicKeyTemplate = new ECDSAPublicKey();
        		publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
        		publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);

        		ObjectID eccCurveObjectID = new ObjectID(objectID);
        		publicKeyTemplate.getEcdsaParams().setByteArrayValue(DerCoder.encode(eccCurveObjectID));

        		PKCS11KeyPairGenerationSpec keyPairGenerationSpec =
        			new PKCS11KeyPairGenerationSpec(tokenManager, publicKeyTemplate, privateKeyTemplate, 
        					PKCS11Spec.USE_READ_WRITE_SESSION, PKCS11Spec.USE_USER_SESSION);

        		keyPairGenerator.initialize(keyPairGenerationSpec);
				*/
        	} else {
        		ECGenParameterSpec ecSpec = new ECGenParameterSpec(name);
        		if (StringUtils.equals(name,"implicitlyCA")) {
        			log.debug("Generating implicitlyCA encoded ECDSA key pair");
        			// If the keySpec is null, we have "implicitlyCA" defined EC parameters
        			// The parameters were already installed when we installed the provider
        			// We just make sure that ecSpec == null here
        			ecSpec = null;
        		}
        		kpg.initialize(ecSpec);        		
        	}
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC name "+name+" not supported.");
            throw e;
        }
        generateKeyPair(kpg, keyEntryName, "SHA1withECDSA");
        if (log.isTraceEnabled()) {
        	log.trace("<generate: curve name "+name+", keyEntryName "+keyEntryName);
        }
    }
    
    private void generateExtraEC(final String name, final String keyEntryName, final String algInstanceName, final String sigAlgName)
            throws InvalidAlgorithmParameterException {
     if (log.isTraceEnabled()) {
            log.trace(">generate "+algInstanceName+": curve name "+name+", keyEntryName "+keyEntryName);
        }
        // Generate the EC Keypair
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(algInstanceName, this.providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + name + "was not recognized.", e);
         } catch (NoSuchProviderException e) {
             throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
         }
        try {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(name);
            kpg.initialize(ecSpec);
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC "+algInstanceName+" name "+name+" not supported.");
            throw e;
        }
        generateKeyPair(kpg, keyEntryName, sigAlgName);
        if (log.isTraceEnabled()) {
            log.trace("<generate: curve name "+name+", keyEntryName "+keyEntryName);
        }
    }

    private void generateGOST3410(final String name, final String keyEntryName) throws
            InvalidAlgorithmParameterException {
        generateExtraEC(name, keyEntryName, AlgorithmConstants.KEYALGORITHM_ECGOST3410, AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410);
    }
    
    private void generateDSTU4145(final String name, final String keyEntryName) throws
            InvalidAlgorithmParameterException {
        generateExtraEC(name, keyEntryName, AlgorithmConstants.KEYALGORITHM_DSTU4145, AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145);
    }

    private void generateRSA(final int keySize, final String keyEntryName) {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
        // Generate the RSA Keypair
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", this.providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + "RSA" + "was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        kpg.initialize(keySize);
        generateKeyPair(kpg, keyEntryName, "SHA1withRSA");
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
    }

    private void generateDSA(final int keySize, final String keyEntryName) {
        if (log.isTraceEnabled()) {
            log.trace(">generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
        }
        // Generate the RSA Keypair
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("DSA", this.providerName);
        } catch (NoSuchAlgorithmException e) {
           throw new IllegalStateException("Algorithm " + "DSA" + "was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        kpg.initialize(keySize);
        generateKeyPair(kpg, keyEntryName, "SHA1withDSA");
        if (log.isTraceEnabled()) {
            log.trace("<generate: keySize " + keySize + ", keyEntryName " + keyEntryName);
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
    	KeyGenerator generator = KeyGenerator.getInstance(algorithm, this.providerName);
        generator.init(keysize);
        Key key = generator.generateKey();
        setKeyEntry(keyEntryName, key, null);
    }

    /** Generates keys in the Keystore token.
     * @param spec AlgorithmParameterSpec for the KeyPairGenerator. Can be anything like RSAKeyGenParameterSpec, DSAParameterSpec, ECParameterSpec or ECGenParameterSpec. 
     * @param keyEntryName
     */
    public void generateKeyPair(final AlgorithmParameterSpec spec, final String keyEntryName) throws InvalidAlgorithmParameterException,
            CertificateException, IOException {
        if (log.isTraceEnabled()) {
        	log.trace(">generate from AlgorithmParameterSpec: "+spec.getClass().getName());
        }
        // Generate the Keypair
        String algorithm = "EC";
        String sigAlg = "SHA1withECDSA";
        String specName = spec.getClass().getName();
        if (specName.contains("DSA")) {
        	algorithm = "DSA";
            sigAlg = "SHA1withDSA";
        } else if (specName.contains("RSA")) {
        	algorithm = "RSA";
            sigAlg = "SHA1withRSA";
        }
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance(algorithm, this.providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm " + algorithm + " was not recognized.", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        try {
            kpg.initialize(spec);
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("Algorithm parameters not supported: "+e.getMessage());
            throw e;
        }
        generateKeyPair(kpg, keyEntryName, sigAlg);
        if (log.isTraceEnabled()) {
        	log.trace("<generate from AlgorithmParameterSpec: "+spec.getClass().getName());
        }
    }
    
    private void generateKeyPair(final KeyPairGenerator kpg, final String keyEntryName, final String sigAlgName) {
        // We will make a loop to retry key generation here. Using the IAIK provider it seems to give
        // CKR_OBJECT_HANDLE_INVALID about every second time we try to store keys
        // But if we try again it succeeds
        int bar = 0;
        while (bar < 3) {
            bar++;
            try {
                log.debug("generating...");
                final KeyPair keyPair = kpg.generateKeyPair();
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = getSelfCertificate("CN=some guy, L=around, C=US", (long) 30 * 24 * 60 * 60 * 365, sigAlgName, keyPair);
                log.debug("Creating certificate with entry " + keyEntryName + '.');
                setKeyEntry(keyEntryName, keyPair.getPrivate(), chain);
                break; // success no need to try more
            } catch (KeyStoreException e) {
                log.info("Failed to generate or store new key, will try 3 times. This was try: " + bar, e);
            } catch(CertificateException e) {
                throw new KeyCreationException("Can't create keystore because dummy certificate chain creation failed.",e);
            } catch (InvalidKeyException e) {
               throw new KeyCreationException("Dummy certificate chain was created with an invalid key" , e);
            }
        }
    }

    /** Generates a certificate request (CSR) in PKCS#10 format and writes to file
     * @param alias for the key to be used
     * @param dn the DN to be used. If null the 'CN=alias' will be used
     * @param explicitEccParameters false should be default and will use NamedCurve encoding of ECC public keys (IETF recommendation), use true to include all parameters explicitly (ICAO ePassport requirement).
     * @throws Exception
     */
    public void generateCertReq(String alias, String sDN, boolean explicitEccParameters) throws Exception {
        PublicKey publicKey = getCertificate(alias).getPublicKey();
        final PrivateKey privateKey = getPrivateKey(alias);
        if (log.isDebugEnabled()) {
            log.debug("alias: " + alias + " SHA1 of public key: " + CertTools.getFingerprintAsString(publicKey.getEncoded()));
        }
        String sigAlg = (String)AlgorithmTools.getSignatureAlgorithms(publicKey).iterator().next();
        if ( sigAlg == null ) {
        	sigAlg = "SHA1WithRSA";
        }
        if (sigAlg.contains("ECDSA") && explicitEccParameters) {
            log.info("Using explicit parameter encoding for ECC key.");
            publicKey = ECKeyUtil.publicToExplicitParameters(publicKey, "BC");
        } else {
            log.info("Using named curve parameter encoding for ECC key.");
        }
        X500Name sDNName = sDN!=null ? new X500Name(sDN) : new X500Name("CN="+alias);
        final PKCS10CertificationRequest certReq =
            CertTools.genPKCS10CertificationRequest( sigAlg,
                                            sDNName,
                                            publicKey, new DERSet(),
                                            privateKey,
                                            this.keyStore.getProvider().getName() );
        ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(publicKey);
        if ( !certReq.isSignatureValid(verifier) ) {
            String msg = intres.getLocalizedMessage("token.errorcertreqverify", alias);
            throw new Exception(msg);
        }
        String filename = alias+".pem";
        final Writer writer = new FileWriter(filename);
        writer.write(CertTools.BEGIN_CERTIFICATE_REQUEST+"\n");
        writer.write(new String(Base64.encode(certReq.getEncoded())));
        writer.write("\n"+CertTools.END_CERTIFICATE_REQUEST+"\n");
        writer.close();
        log.info("Wrote csr to file: "+filename);
    }
    
    /**
     * Install certificate chain to key in keystore.
     * @param file name of the file with chain. Starting with the certificate of the key. Ending with the root certificate.
     * @throws Exception
     */
    public void installCertificate(final String fileName) throws Exception {
        final X509Certificate chain[] = ((Collection<?>)CertTools.getCertsFromPEM(new FileInputStream(fileName))).toArray(new X509Certificate[0]);
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
            throw new Exception(msg);
        }
    }
    
    /**
     * Install trusted root in trust store
     * @param File name of the trusted root.
     * @throws Exception
     */
    public void installTrustedRoot(String fileName) throws Exception {
        final X509Certificate chain[] = ((Collection<?>)CertTools.getCertsFromPEM(new FileInputStream(fileName))).toArray(new X509Certificate[0]);
        if ( chain.length<1 ) {
            throw new Exception("No certificate in file");
        }
        // assume last cert in chain is root if more than 1
        getKeyStore().setCertificateEntry("trusted", chain[chain.length-1]);
    }
    private PrivateKey getPrivateKey(String alias) throws Exception {
        final PrivateKey key = (PrivateKey)getKey(alias);
        if ( key==null ) {
            String msg = intres.getLocalizedMessage("token.errornokeyalias", alias);
            log.info(msg);
        }
        return key;
    }
    private Key getKey(String alias) throws Exception, IOException {
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
