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
package org.ejbca.util.keystore;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * @version $Id$
 */
public abstract class KeyStoreContainer {
    private static final Logger log = Logger.getLogger(KeyStoreContainer.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    protected final KeyStore keyStore;
    private final String providerName;
    private final String ecryptProviderName;
    public static KeyStoreContainer getInstance(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final String storeID) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, LoginException {
    	log.debug("keyStoreType "+keyStoreType+", providerClassName "+providerClassName+", encryptProviderClassName "+encryptProviderClassName+", storeID "+storeID);
        Security.addProvider( new BouncyCastleProvider() );
        if ( isP11(keyStoreType) ) {
            final char firstChar = storeID!=null && storeID.length()>0 ? storeID.charAt(0) : '\0';
            final String slotID;
            final boolean isIndex;
            if ( firstChar=='i'||firstChar=='I' ) {
                slotID = storeID.substring(1);
                isIndex = true;
            } else {
                slotID = storeID;
                isIndex = false;
            }
            return KeyStoreContainerP11.getInstance( slotID,
                                               providerClassName,
                                               isIndex, null);
        } else
            return KeyStoreContainerJCE.getInstance( keyStoreType,
                                               providerClassName,
                                               encryptProviderClassName,
                                               storeID!=null ? storeID.getBytes():null);
    }
    public static boolean isP11(String keyStoreType) {
        return keyStoreType.toLowerCase().indexOf("pkcs11") >= 0;
    }
    KeyStoreContainer( KeyStore _keyStore,
                       String _providerName,
                       String _ecryptProviderName ){
        this.keyStore = _keyStore;
        this.providerName = _providerName;
        this.ecryptProviderName = _ecryptProviderName;
    }
    public String getProviderName() {
        return this.providerName;
    }
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    abstract void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException;
    abstract public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException;
    abstract public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException;
    abstract public char[] getPassPhraseGetSetEntry();
    void deleteAlias(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
    	String msg = intres.getLocalizedMessage("catoken.deletecert", alias);
        log.info(msg);
    }
    public byte[] delete(final String alias) throws Exception {
        if ( alias!=null )
            deleteAlias(alias);
        else {
            Enumeration e = this.keyStore.aliases();
            while( e.hasMoreElements() )
                deleteAlias( (String) e.nextElement() );
        }
        return storeKeyStore();
    }
    private X509Certificate getSelfCertificate (String myname,
                                                long validity,
                                                String sigAlg,
                                                KeyPair keyPair) throws CertificateException, InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
        // Add all mandatory attributes
        cg.setSerialNumber(BigInteger.valueOf(firstDate.getTime()));
        cg.setSignatureAlgorithm(sigAlg);
        cg.setSubjectDN(new X500Principal(myname));
        cg.setPublicKey(keyPair.getPublic());
        cg.setNotBefore(firstDate);
        cg.setNotAfter(lastDate);
        cg.setIssuerDN(new X500Principal(myname));
        return cg.generate(keyPair.getPrivate(), this.providerName);
    }
    private KeyPair generate( final String provider,
                              final String algName,
                              final int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, provider);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }
    public byte[] generate( final int keySize,
                            final String keyEntryName) throws Exception {
        // Generate the RSA Keypair
    	log.debug(">generate: keySize"+keySize+", keyEntryName"+keyEntryName);
        final String keyAlgName = "RSA";
        final String sigAlgName = "SHA1withRSA";
        final KeyPair keyPair = generate(this.providerName, keyAlgName, keySize);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                      (long)30*24*60*60*365, sigAlgName, keyPair);
        log.debug("Creating certificate with entry "+keyEntryName+'.');
        setKeyEntry(keyEntryName, keyPair.getPrivate(), chain);
        return storeKeyStore();
    }
    
    /** Moves an entry in a keystore from an alias (fromID) to another (toID) 
     */
    public static void move(final String providerClassName,
                     final String encryptProviderClassName,
                     final String keyStoreType,
                     final String fromID,
                     final String toID) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, LoginException {
        KeyStoreContainer fromKS = getInstance(keyStoreType, providerClassName, encryptProviderClassName, fromID);
        KeyStoreContainer toKS = getInstance(keyStoreType, providerClassName, encryptProviderClassName, toID);
        Enumeration e = fromKS.getKeyStore().aliases();
        while( e.hasMoreElements() ) {
            String alias = (String) e.nextElement();
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
    
    abstract private class CodeStream {
        void code(InputStream is, OutputStream os, String alias) throws Exception {
        	doCoding(is, os, alias);
        	os.flush();
        }
        abstract void doCoding(final InputStream is, OutputStream os, String alias) throws Exception;
    }
    
    private class EncryptStream extends CodeStream {
        void doCoding(final InputStream is, OutputStream os, String alias) throws Exception {
            final int bufferSize = 32*1024;
            final InputStream bis = new BufferedInputStream(is, bufferSize);
            final OutputStream bos = new BufferedOutputStream(os, bufferSize);
            final CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
            final Certificate cert = keyStore.getCertificate(alias);
            if ( cert==null ) {
            	String msg = intres.getLocalizedMessage("catoken.errornocertalias", alias);
                throw new ErrorAdminCommandException(msg);
            }
            edGen.addKeyTransRecipient(cert.getPublicKey(), "hej".getBytes() );
            OutputStream out = edGen.open(bos, CMSEnvelopedDataGenerator.AES128_CBC, "BC");
            byte[] buf = new byte[bufferSize];
            while (true) {
            	int len = bis.read(buf);
                if ( len<0 )
                    break;
                out.write(buf,0, len);
            }
            out.close();
            bos.close();
            os.close();
        }
    }
    private class DecryptStream extends CodeStream {
        void doCoding(final InputStream is, OutputStream os, String alias) throws Exception  {
            final int bufferSize = 32*1024;
            final InputStream bis = new BufferedInputStream(is, bufferSize);
            final OutputStream bos = new BufferedOutputStream(os, bufferSize);
            CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(bis);
            RecipientInformationStore  recipients = ep.getRecipientInfos();        
            Collection  c = recipients.getRecipients();
            Iterator    it = c.iterator();
            if (it.hasNext()) {
                RecipientInformation   recipient = (RecipientInformation)it.next();
                final Key key = getKey(alias);
                if ( key==null ) {
                	String msg = intres.getLocalizedMessage("catoken.errornokeyalias", alias);
                    throw new ErrorAdminCommandException(msg);
                }
                CMSTypedStream recData = recipient.getContentStream(key, KeyStoreContainer.this.ecryptProviderName);
                InputStream ris = recData.getContentStream();
                byte[] buf = new byte[bufferSize];
                while (true) {
                	int len = ris.read(buf);
                	if ( len<0 )
                        break;
                    bos.write(buf,0, len);
                }            
            }
            bos.close();
            os.close();
        }
    }
    public void decrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new DecryptStream().code(is, os, alias);
    }
    public void encrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new EncryptStream().code(is, os, alias);
    }
    public void generateCertReq(String alias) throws Exception {
        final RSAPublicKey publicKey = (RSAPublicKey)keyStore.getCertificate(alias).getPublicKey();
        final PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias, null);
        final PKCS10CertificationRequest certReq =
            new PKCS10CertificationRequest( "SHA1withRSA",
                                            new X509Name("CN="+alias),
                                            publicKey, new DERSet(),
                                            privateKey,
                                            keyStore.getProvider().getName() );
        if ( !certReq.verify() ) {
        	String msg = intres.getLocalizedMessage("catoken.errorcertreqverify", alias);
            throw new Exception(msg);
        }
        final Writer writer = new FileWriter(alias+".pem");
        writer.write(new String(Base64.encode(certReq.getEncoded())));
        writer.close();
    }
    public void installCertificate(final String fileName) throws Exception {
        final X509Certificate chain[] = (X509Certificate[])CertTools.getCertsFromPEM(new FileInputStream(fileName)).toArray(new X509Certificate[0]);
        final Enumeration eAlias = keyStore.aliases();
        String alias = null;
        while ( eAlias.hasMoreElements() ) {
            alias = (String)eAlias.nextElement();
            if ( keyStore.getCertificate(alias).getPublicKey().equals(chain[0].getPublicKey()) )
                break;
        }
        if ( alias==null ) {
        	String msg = intres.getLocalizedMessage("catoken.errorkeynottoken", alias);
            throw new Exception(msg);
        }
        keyStore.setKeyEntry(alias, keyStore.getKey(alias, null), null, chain);
    }
}
