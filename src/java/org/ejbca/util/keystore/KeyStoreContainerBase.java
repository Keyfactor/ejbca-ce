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
package org.ejbca.util.keystore;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.ECKeyUtil;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CMS;

/**
 * @version $Id$
 */
public abstract class KeyStoreContainerBase implements KeyStoreContainer {
    private static final Logger log = Logger.getLogger(KeyStoreContainerBase.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    protected final KeyStore keyStore;
    private final String providerName;
    private final String ecryptProviderName;
    private char passPhraseLoadSave[] = null;

    KeyStoreContainerBase( KeyStore _keyStore,
                           String _providerName,
                           String _ecryptProviderName ){
        this.keyStore = _keyStore;
        this.providerName = _providerName;
        this.ecryptProviderName = _ecryptProviderName;
    }
    @Override
    public String getProviderName() {
        return this.providerName;
    }
    @Override
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    abstract void setKeyEntry(String alias, Key key, Certificate chain[]) throws Exception;
    @Override
    public void setPassPhraseLoadSave(char[] passPhrase) {
        this.passPhraseLoadSave = passPhrase;
    }
    protected char[] getPassPhraseLoadSave() {
        return this.passPhraseLoadSave;
    }
    void deleteAlias(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
        String msg = intres.getLocalizedMessage("catoken.deletecert", alias);
        log.info(msg);
    }
    @Override
    public byte[] delete(final String alias) throws Exception {
        if ( alias!=null ) {
            deleteAlias(alias);
        } else {
            Enumeration<String> e = this.keyStore.aliases();
            while( e.hasMoreElements() ) {
                deleteAlias( e.nextElement() );
            }
        }
        return storeKeyStore();
    }
    @Override
    public byte[] renameAlias( String oldAlias, String newAlias ) throws Exception {
        this.keyStore.setEntry(newAlias, this.keyStore.getEntry(oldAlias, null), null);
        return storeKeyStore();
    }
    private X509Certificate getSelfCertificate (String myname,
                                                long validity,
                                                String sigAlg,
                                                KeyPair keyPair) throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        // Add all mandatory attributes
        log.debug("keystore signing algorithm "+sigAlg);
        final PublicKey publicKey = keyPair.getPublic();
        if ( publicKey==null ) {
            throw new Exception("Public key is null");
        }
        
        final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(publicKey.getEncoded()));
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(new X500Name(myname), BigInteger.valueOf(firstDate.getTime()), firstDate, lastDate, new X500Name(myname), pkinfo);
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(sigAlg).setProvider(this.providerName).build(keyPair.getPrivate()), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        return (X509Certificate) CertTools.getCertfromByteArray(certHolder.getEncoded());
    }
    /** 
     * @see org.ejbca.util.keystore.KeyStoreContainer#generate(java.lang.String, java.lang.String)
     */
    private byte[] generateEC( final String name,
                              final String keyEntryName) throws Exception {
        if (log.isTraceEnabled()) {
        	log.trace(">generate EC: curve name "+name+", keyEntryName "+keyEntryName);
        }
        // Generate the EC Keypair
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", this.providerName);
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
                kpg.initialize(new ECGenParameterSpec(name));        		
        	}
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC name "+name+" not supported.");
            throw e;
        }
        final byte result[] = generate(kpg, keyEntryName, "SHA1withECDSA");
        if (log.isTraceEnabled()) {
        	log.trace("<generate: curve name "+name+", keyEntryName "+keyEntryName);
        }
        return result;
    }
    /** 
     * @see org.ejbca.util.keystore.KeyStoreContainer#generate(int, java.lang.String)
     */
    private byte[] generateRSA(final int keySize,
                            final String keyEntryName) throws Exception {
    	if (log.isTraceEnabled()) {
    		log.trace(">generate: keySize "+keySize+", keyEntryName "+keyEntryName);
    	}
        // Generate the RSA Keypair
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", this.providerName);
        kpg.initialize(keySize);
        final byte result[] = generate(kpg, keyEntryName, "SHA1withRSA");
        if (log.isTraceEnabled()) {
        	log.trace("<generate: keySize "+keySize+", keyEntryName "+keyEntryName);
        }
        return result;
    }
    /** 
     * @see org.ejbca.util.keystore.KeyStoreContainer#generate(int, java.lang.String)
     */
    private byte[] generateDSA( final int keySize,
                               final String keyEntryName) throws Exception {
     	if (log.isTraceEnabled()) {
    		log.trace(">generate: keySize "+keySize+", keyEntryName "+keyEntryName);
    	}
        // Generate the RSA Keypair
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA", this.providerName);
        kpg.initialize(keySize);
        final byte result[] = generate(kpg, keyEntryName, "SHA1withDSA");
        if (log.isTraceEnabled()) {
        	log.trace("<generate: keySize "+keySize+", keyEntryName "+keyEntryName);
        }
        return result;
    }
    @Override
    public byte[] generate( final String keySpec,
                            final String keyEntryName) throws Exception {
    	if (keySpec.toUpperCase ().startsWith ("DSA")) {
    		return generateDSA (Integer.parseInt(keySpec.substring(3).trim()), keyEntryName);
    	}
        try {
            return generateRSA(Integer.parseInt(keySpec.trim()), keyEntryName);
        } catch (NumberFormatException e) {
            return generateEC(keySpec, keyEntryName);
        }
    }
    @Override
    public byte[] generate( final AlgorithmParameterSpec spec,
    		                final String keyEntryName) throws Exception {
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
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, this.providerName);
        try {
            kpg.initialize(spec);
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("Algorithm parameters not supported: "+e.getMessage());
            throw e;
        }
        final byte result[] = generate(kpg, keyEntryName, sigAlg);
        if (log.isTraceEnabled()) {
        	log.trace("<generate from AlgorithmParameterSpec: "+spec.getClass().getName());
        }
        return result;
    }
    
    private byte[] generate( final KeyPairGenerator kpg,
                             final String keyEntryName,
                             final String sigAlgName ) throws Exception {
        // We will make a loop to retry key generation here. Using the IAIK provider it seems to give
        // CKR_OBJECT_HANDLE_INVALID about every second time we try to store keys
        // But if we try again it succeeds
        int bar = 0;
        while (bar < 3) {
            bar ++;
            try {
                log.debug("generating...");
                final KeyPair keyPair = kpg.generateKeyPair();
                X509Certificate[] chain = new X509Certificate[1];
                chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                              (long)30*24*60*60*365, sigAlgName, keyPair);
                log.debug("Creating certificate with entry "+keyEntryName+'.');
                setKeyEntry(keyEntryName, keyPair.getPrivate(), chain);
                break; // success no need to try more
            } catch (KeyStoreException e) {
                log.info("Failed to generate or store new key, will try 3 times. This was try: "+bar, e);
            }
        }
        return storeKeyStore();
    }

    /** Moves an entry in a keystore from an alias (fromID) to another (toID) 
     * 
     * @param pp KeyStore.ProtectionParameter if null a default (prompting) is used
     */
    public static void move(final String providerClassName,
                            final String encryptProviderClassName,
                            final String keyStoreType,
                            final String fromID,
                            final String toID,
                            final Pkcs11SlotLabelType slotLabelType,
                            KeyStore.ProtectionParameter pp) throws Exception {
        KeyStoreContainerBase fromKS = (KeyStoreContainerBase)KeyStoreContainerFactory.getInstance(keyStoreType, providerClassName, encryptProviderClassName, fromID, slotLabelType, null, pp);
        KeyStoreContainerBase toKS = (KeyStoreContainerBase)KeyStoreContainerFactory.getInstance(keyStoreType, providerClassName, encryptProviderClassName, toID, slotLabelType, null, pp);
        Enumeration<String> e = fromKS.getKeyStore().aliases();
        while( e.hasMoreElements() ) {
            String alias = e.nextElement();
            if (fromKS.getKeyStore().isKeyEntry(alias)) {
                Key key=fromKS.getKey(alias);
                Certificate chain[] = fromKS.getKeyStore().getCertificateChain(alias);
                toKS.setKeyEntry(alias, key, chain);
            }
            fromKS.deleteAlias( alias );
        }
        fromKS.storeKeyStore();
        toKS.storeKeyStore();
    }
    @Override
    public void decrypt(InputStream is, OutputStream os, String alias) throws Exception {
        CMS.decrypt(is, os, getPrivateKey(alias), KeyStoreContainerBase.this.ecryptProviderName);
    }
    @Override
    public void encrypt(final InputStream is, final OutputStream os, final String alias, final String symmAlgOid) throws Exception {
        CMS.encrypt(is, os, getCertificate(alias), symmAlgOid);
    }
    @Override
    public void sign(InputStream in, OutputStream out, String alias) throws Exception {
        CMS.sign(in, out, getPrivateKey(alias), KeyStoreContainerBase.this.providerName, getCertificate(alias));
    }
    @Override
    public CMS.VerifyResult verify(InputStream in, OutputStream out, String alias) throws Exception {
        return CMS.verify(in, out, getCertificate(alias));
    }
    @Override
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
    @Override
    public void installCertificate(final String fileName) throws Exception {
        log.info("Installing " + fileName + ": ");
        final X509Certificate chain[] = ((Collection<?>)CertTools.getCertsFromPEM(new FileInputStream(fileName))).toArray(new X509Certificate[0]);
        final Enumeration<String> eAlias = this.keyStore.aliases();
        boolean notFound = true;
        while ( eAlias.hasMoreElements() && notFound ) {
            final String alias = eAlias.nextElement();
            final PublicKey hsmPublicKey = getCertificate(alias).getPublicKey();
            final PublicKey importPublicKey = chain[0].getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug("alias: " + alias + " SHA1 of public hsm key: " + CertTools.getFingerprintAsString(hsmPublicKey.getEncoded())
                          + " SHA1 of first public key in chain: " + CertTools.getFingerprintAsString(importPublicKey.getEncoded())
                          +  (chain.length==1?"":("SHA1 of last public key in chain: " + CertTools.getFingerprintAsString(chain[chain.length-1].getPublicKey().getEncoded()))));
            }
            if ( hsmPublicKey.equals(importPublicKey) ) {
                log.info("Found a matching public key for alias \"" + alias + "\".");
                this.keyStore.setKeyEntry(alias, getPrivateKey(alias), null, chain);
                notFound = false;
            }
        }
        if ( notFound ) {
            final String msg = intres.getLocalizedMessage("token.errorkeynottoken");
            throw new Exception(msg);
        }
    }
    @Override
    public void installTrustedRoot(String fileName) throws Exception {
        final X509Certificate chain[] = ((Collection<?>)CertTools.getCertsFromPEM(new FileInputStream(fileName))).toArray(new X509Certificate[0]);
        if ( chain.length<1 ) {
            throw new Exception("No certificate in file");
        }
        // assume last cert in chain is root if more than 1
        this.keyStore.setCertificateEntry("trusted", chain[chain.length-1]);
    }
    private PrivateKey getPrivateKey(String alias) throws Exception {
        final PrivateKey key = (PrivateKey)getKey(alias);
        if ( key==null ) {
            String msg = intres.getLocalizedMessage("token.errornokeyalias", alias);
            throw new ErrorAdminCommandException(msg);
        }
        return key;
    }
    private X509Certificate getCertificate( String alias ) throws KeyStoreException, ErrorAdminCommandException {
        final X509Certificate cert = (X509Certificate)this.keyStore.getCertificate(alias);
        if ( cert==null ) {
            String msg = intres.getLocalizedMessage("token.errornocertalias", alias);
            throw new ErrorAdminCommandException(msg);
        }
        return cert;
    }
}
