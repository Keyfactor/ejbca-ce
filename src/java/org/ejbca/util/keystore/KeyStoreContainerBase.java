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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSEnvelopedGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.ejbca.core.model.InternalResources;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * @version $Id: KeyStoreContainer.java 6102 2008-08-20 17:34:30Z primelars $
 */
public abstract class KeyStoreContainerBase implements KeyStoreContainer {
    private static final Logger log = Logger.getLogger(KeyStoreContainerBase.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

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
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#getProviderName()
     */
    public String getProviderName() {
        return this.providerName;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#getKeyStore()
     */
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    abstract void setKeyEntry(String alias, Key key, Certificate chain[]) throws Exception;
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#setPassPhraseLoadSave(char[])
     */
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
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#delete(java.lang.String)
     */
    public byte[] delete(final String alias) throws Exception {
        if ( alias!=null )
            deleteAlias(alias);
        else {
            Enumeration<String> e = this.keyStore.aliases();
            while( e.hasMoreElements() )
                deleteAlias( e.nextElement() );
        }
        return storeKeyStore();
    }
    private X509Certificate getSelfCertificate (String myname,
                                                long validity,
                                                String sigAlg,
                                                KeyPair keyPair) throws Exception {
        final long currentTime = new Date().getTime();
        final Date firstDate = new Date(currentTime-24*60*60*1000);
        final Date lastDate = new Date(currentTime + validity * 1000);
        X509V3CertificateGenerator cg = new X509V3CertificateGenerator();
        // Add all mandatory attributes
        cg.setSerialNumber(BigInteger.valueOf(firstDate.getTime()));
        log.debug("keystore signing algorithm "+sigAlg);
        cg.setSignatureAlgorithm(sigAlg);
        cg.setSubjectDN(new X500Principal(myname));
        final PublicKey publicKey = keyPair.getPublic();
        if ( publicKey==null )
            throw new Exception("Public key is null");
        cg.setPublicKey(publicKey);
        cg.setNotBefore(firstDate);
        cg.setNotAfter(lastDate);
        cg.setIssuerDN(new X500Principal(myname));
        return cg.generate(keyPair.getPrivate(), this.providerName);
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#generateEC(java.lang.String, java.lang.String)
     */
    public byte[] generateEC( final String name,
                              final String keyEntryName) throws Exception {
        // Generate the EC Keypair
        log.debug(">generate EC: curve name "+name+", keyEntryName "+keyEntryName);
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", this.providerName);
        try {
            kpg.initialize(new ECGenParameterSpec(name));
        } catch( InvalidAlgorithmParameterException e ) {
            log.debug("EC name "+name+" not supported.");
            throw e;
        }
        final byte result[] = generate(kpg, keyEntryName, "SHA1withECDSA");
        log.debug("<generate: curve name "+name+", keyEntryName "+keyEntryName);
        return result;

    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#generate(int, java.lang.String)
     */
    public byte[] generate( final int keySize,
                            final String keyEntryName) throws Exception {
        // Generate the RSA Keypair
        log.debug(">generate: keySize "+keySize+", keyEntryName "+keyEntryName);
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", this.providerName);
        kpg.initialize(keySize);
        final byte result[] = generate(kpg, keyEntryName, "SHA1withRSA");
        log.debug("<generate: keySize "+keySize+", keyEntryName "+keyEntryName);
        return result;
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#generate(java.lang.String, java.lang.String)
     */
    public byte[] generate( final String algName,
                            final String keyEntryName) throws Exception {
        try {
            return generate(Integer.parseInt(algName.trim()), keyEntryName);
        } catch (NumberFormatException e) {
            return generateEC(algName, keyEntryName);
        }
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
                            KeyStore.ProtectionParameter pp) throws Exception {
        KeyStoreContainerBase fromKS = (KeyStoreContainerBase)KeyStoreContainerFactory.getInstance(keyStoreType, providerClassName, encryptProviderClassName, fromID, null, pp);
        KeyStoreContainerBase toKS = (KeyStoreContainerBase)KeyStoreContainerFactory.getInstance(keyStoreType, providerClassName, encryptProviderClassName, toID, null, pp);
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
            final Certificate cert = KeyStoreContainerBase.this.keyStore.getCertificate(alias);
            if ( cert==null ) {
                String msg = intres.getLocalizedMessage("catoken.errornocertalias", alias);
                throw new ErrorAdminCommandException(msg);
            }
            edGen.addKeyTransRecipient(cert.getPublicKey(), "hej".getBytes() );
            OutputStream out = edGen.open(bos, CMSEnvelopedGenerator.AES128_CBC, "BC");
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
            Collection<?>  c = recipients.getRecipients();
            Iterator<?>  it = c.iterator();
            if (it.hasNext()) {
                RecipientInformation   recipient = (RecipientInformation)it.next();
                final Key key = getKey(alias);
                if ( key==null ) {
                    String msg = intres.getLocalizedMessage("catoken.errornokeyalias", alias);
                    throw new ErrorAdminCommandException(msg);
                }
                CMSTypedStream recData = recipient.getContentStream(key, KeyStoreContainerBase.this.ecryptProviderName);
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
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#decrypt(java.io.InputStream, java.io.OutputStream, java.lang.String)
     */
    public void decrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new DecryptStream().code(is, os, alias);
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#encrypt(java.io.InputStream, java.io.OutputStream, java.lang.String)
     */
    public void encrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new EncryptStream().code(is, os, alias);
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#generateCertReq(java.lang.String)
     */
    public void generateCertReq(String alias) throws Exception {
        final RSAPublicKey publicKey = (RSAPublicKey)this.keyStore.getCertificate(alias).getPublicKey();
        final PrivateKey privateKey = (PrivateKey)this.keyStore.getKey(alias, null);
        final PKCS10CertificationRequest certReq =
            new PKCS10CertificationRequest( "SHA1withRSA",
                                            new X509Name("CN="+alias),
                                            publicKey, new DERSet(),
                                            privateKey,
                                            this.keyStore.getProvider().getName() );
        if ( !certReq.verify() ) {
            String msg = intres.getLocalizedMessage("catoken.errorcertreqverify", alias);
            throw new Exception(msg);
        }
        final Writer writer = new FileWriter(alias+".pem");
        writer.write(new String(Base64.encode(certReq.getEncoded())));
        writer.close();
    }
    /* (non-Javadoc)
     * @see org.ejbca.util.keystore.KeyStoreContainer#installCertificate(java.lang.String)
     */
    public void installCertificate(final String fileName) throws Exception {
        final X509Certificate chain[] = ((Collection<?>)CertTools.getCertsFromPEM(new FileInputStream(fileName))).toArray(new X509Certificate[0]);
        final Enumeration<String> eAlias = this.keyStore.aliases();
        String alias = null;
        while ( eAlias.hasMoreElements() ) {
            alias = eAlias.nextElement();
            if ( this.keyStore.getCertificate(alias).getPublicKey().equals(chain[0].getPublicKey()) )
                break;
        }
        if ( alias==null ) {
            String msg = intres.getLocalizedMessage("catoken.errorkeynottoken", alias);
            throw new Exception(msg);
        }
        this.keyStore.setKeyEntry(alias, this.keyStore.getKey(alias, null), null, chain);
    }
}
