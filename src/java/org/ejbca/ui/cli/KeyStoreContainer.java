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
package org.ejbca.ui.cli;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.AuthProvider;
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
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

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
import org.ejbca.ui.cli.util.ConsolePasswordReader;
import org.ejbca.ui.cli.util.PasswordReader;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

/**
 * @version $Id$
 */
public abstract class KeyStoreContainer {

    /** The name of Suns textcallbackhandler (for pkcs11) implementation */
    public static final String SUNTEXTCBHANDLERCLASS = "com.sun.security.auth.callback.TextCallbackHandler";

    protected final KeyStore keyStore;
    private final String providerName;
    private final String ecryptProviderName;
    static KeyStoreContainer getIt(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final String storeID) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, LoginException {
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
            return KeyStoreContainerP11.getIt( slotID,
                                               providerClassName,
                                               isIndex );
        } else
            return KeyStoreContainerJCE.getIt( keyStoreType,
                                               providerClassName,
                                               encryptProviderClassName,
                                               storeID!=null ? storeID.getBytes():null);
    }
    static boolean isP11(String keyStoreType) {
        return keyStoreType.toLowerCase().indexOf("pkcs11") >= 0;
    }
    KeyStoreContainer( KeyStore _keyStore,
                       String _providerName,
                       String _ecryptProviderName ){
        this.keyStore = _keyStore;
        this.providerName = _providerName;
        this.ecryptProviderName = _ecryptProviderName;
    }
    String getProviderName() {
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
        System.err.println("Deleting certificate with alias "+alias+'.');
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
        final String keyAlgName = "RSA";
        final String sigAlgName = "SHA1withRSA";
        final KeyPair keyPair = generate(this.providerName, keyAlgName, keySize);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                      (long)30*24*60*60*365, sigAlgName, keyPair);
        System.err.println("Creating certificate with entry "+keyEntryName+'.');
        setKeyEntry(keyEntryName, keyPair.getPrivate(), chain);
        return storeKeyStore();
    }
    static void move(final String providerClassName,
                     final String encryptProviderClassName,
                     final String keyStoreType,
                     final String fromID,
                     final String toID) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException, LoginException {
        KeyStoreContainer fromKS = getIt(keyStoreType, providerClassName, encryptProviderClassName, fromID);
        KeyStoreContainer toKS = getIt(keyStoreType, providerClassName, encryptProviderClassName, toID);
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
            if ( cert==null )
                throw new ErrorAdminCommandException("Certificate alias "+alias+" not found in keystore.");
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
                if ( key==null )
                    throw new ErrorAdminCommandException("Key alias "+alias+" not found in keystore.");
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
                                            publicKey, null,
                                            privateKey,
                                            keyStore.getProvider().getName() );
        if ( !certReq.verify() )
            throw new Exception("Certificate request is not verifying.");
        final Writer writer = new FileWriter(alias+".pem");
        writer.write(new String(Base64.encode(certReq.getEncoded())));
        writer.close();
    }
    public void installCertificate(final String fileName) throws Exception {
        final X509Certificate chain[] = (X509Certificate[])CertTools.getCertsFromPEM(new FileInputStream(fileName)).toArray(new X509Certificate[0]);
        final Enumeration<String> eAlias = keyStore.aliases();
        String alias = null;
        while ( eAlias.hasMoreElements() ) {
            alias = eAlias.nextElement();
            if ( keyStore.getCertificate(alias).getPublicKey().equals(chain[0].getPublicKey()) )
                break;
        }
        if ( alias==null )
            throw new Exception("Key not on token.");
        keyStore.setKeyEntry(alias, keyStore.getKey(alias, null), null, chain);
    }
}
class KeyStoreContainerJCE extends KeyStoreContainer {
    private final PasswordReader passwordReader;
    private char passPhraseLoadSave[] = null;
    private char passPhraseGetSetEntry[] = null;
    private KeyStoreContainerJCE( final KeyStore _keyStore,
                                  final String _providerName,
                                  final String _ecryptProviderName,
                                  final byte storeID[],
                                  final PasswordReader _passwordReader) throws NoSuchAlgorithmException, CertificateException, IOException{
        super( _keyStore, _providerName, _ecryptProviderName );
        this.passwordReader = _passwordReader!=null ? _passwordReader : new ConsolePasswordReader();
        load(storeID);
    }
    
    static KeyStoreContainer getIt(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final byte storeID[]) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        return getIt( keyStoreType,
                      providerClassName,
                      encryptProviderClassName,
                      storeID,
                      null );
    }
    static KeyStoreContainer getIt(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final byte storeID[],
                                   final PasswordReader passwordReader) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        final String providerName = getProviderName(providerClassName);
        final String ecryptProviderName; {
            String tmp;
            try {
                tmp = getProviderName(encryptProviderClassName);
            } catch( ClassNotFoundException e ) {
                tmp = providerName;
            }
            ecryptProviderName = tmp;
        }
        System.err.println("Creating KeyStore of type "+keyStoreType+" with provider "+providerName+(storeID!=null ? (" with ID "+new String(storeID)) : "")+'.');
        final KeyStore keyStore = KeyStore.getInstance(keyStoreType, providerName);
        return new KeyStoreContainerJCE( keyStore,
                                         providerName,
                                         ecryptProviderName,
                                         storeID,
                                         passwordReader);
    }
    private void setPassWord(boolean isKeystoreException) throws IOException {
        System.err.println((isKeystoreException ? "Setting key entry in keystore" : "Loading keystore")+". Give password of inserted card in slot:");
        final char result[] = passwordReader.readPassword();
        if ( isKeystoreException )
            this.passPhraseGetSetEntry = result;
        else
            this.passPhraseLoadSave = result;
    }
    protected void load(byte storeID[]) throws NoSuchAlgorithmException, CertificateException, IOException {
        try {
            loadHelper(storeID);
        } catch( IOException e ) {
            setPassWord(false);
            loadHelper(storeID);
        }
    }
    private void loadHelper(byte storeID[]) throws NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.load(storeID!=null ? new ByteArrayInputStream(storeID):null, this.passPhraseLoadSave);
    }
    private static String getProviderName( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Object[0]);
        Security.addProvider(provider);
        return provider.getName();
    }
    public char[] getPassPhraseGetSetEntry() {
        return passPhraseGetSetEntry;
    }
    public char[] getPassPhraseLoadSave() {
        return passPhraseLoadSave;
    }
    public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        System.err.println("Next line will contain the identity identifying the keystore:");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.keyStore.store(baos, this.passPhraseLoadSave);
        System.out.print(new String(baos.toByteArray()));
        System.out.flush();
        System.err.println();
        return baos.toByteArray();
    }
    void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
        try {
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        } catch (KeyStoreException e) {
            setPassWord(true);
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        }
    }
    public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
        try {
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry);
        } catch (UnrecoverableKeyException e1) {
            setPassWord(true);
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry );
        }
    }
}
class KeyStoreContainerP11 extends KeyStoreContainer {
    private KeyStoreContainerP11( KeyStore _keyStore,
                                  String _providerName,
                                  String _ecryptProviderName ) throws NoSuchAlgorithmException, CertificateException, IOException{
        super( _keyStore, _providerName, _ecryptProviderName );
        load();
    }
    protected void load() throws NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.load(null, null);
    }
    static KeyStoreContainer getIt(final String slot,
                                   final String libName,
                                   final boolean isIx) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, LoginException {
        AuthProvider provider = KeyTools.getP11AuthProvider(slot, libName, isIx);
        final String providerName = provider.getName();
        Security.addProvider(provider);
        CallbackHandler cbh = null;
    	try {
    		// We will construct the PKCS11 text callback handler (sun.security...) using reflection, because 
    		// the sun class does not exist on other JDKs than sun, and we want to be able to compile everything on i.e. IBM JDK.
    		//   return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
    		final Class implClass = Class.forName(SUNTEXTCBHANDLERCLASS);
    		cbh = (CallbackHandler)implClass.newInstance();
    	} catch (Exception e) {
            System.err.println("Error constructing pkcs11 text callback handler:");
    		e.printStackTrace();
    		IOException ioe = new IOException("Error constructing pkcs11 text callback handler: "+e.getMessage());
    		ioe.initCause(e);
    		throw ioe;
    	} 
        // The above code replaces the single line:
        //final CallbackHandler cbh = new TextCallbackHandler();
        KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider,
                                                                new CallbackHandlerProtection(cbh));
        final KeyStore keyStore = builder.getKeyStore();
        return new KeyStoreContainerP11( keyStore, providerName, providerName );
    }
    public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.store(null, null);
        return new byte[0];
    }
    void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, null, chain);
    }
    public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
        return this.keyStore.getKey(alias, null);
    }
    public char[] getPassPhraseGetSetEntry() {
        return null;
    }
}
