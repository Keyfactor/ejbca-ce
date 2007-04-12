/**
 * 
 */
package org.ejbca.ui.cli;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
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
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import sun.security.pkcs11.SunPKCS11;

import com.sun.security.auth.callback.TextCallbackHandler;

public abstract class KeyStoreContainer {
    protected final KeyStore keyStore;
    private final String providerName;
    private final String ecryptProviderName;
    static KeyStoreContainer getIt(final String keyStoreType,
                                   final String providerClassName,
                                   final String encryptProviderClassName,
                                   final String storeID) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, LoginException {
        if ( isP11(keyStoreType) )
            return KeyStoreContainerP11.getIt( Integer.parseInt(storeID),
                                               providerClassName );
        else
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
            Enumeration<String> e = this.keyStore.aliases();
            while( e.hasMoreElements() )
                deleteAlias( e.nextElement() );
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
            edGen.addKeyTransRecipient(keyStore.getCertificate(alias).getPublicKey(), "hej".getBytes() );
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
                CMSTypedStream recData = recipient.getContentStream(getKey(alias), KeyStoreContainer.this.ecryptProviderName);
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
    public static AuthProvider getP11AuthProvider(final int slot,
                                               final String libName) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(baos);
        final File libFile = new File(libName);
        if ( !libFile.isFile() || !libFile.canRead() )
            throw new IOException("The shared library PKCS11 file "+libName+" can't be read.");
        pw.println("name = "+libFile.getName()+"-slot"+slot);
        pw.println("library = "+libFile.getCanonicalPath());
        pw.println("slot = "+slot);
        pw.flush();
        pw.close();
        return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
        
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
        this.passwordReader = _passwordReader!=null ? _passwordReader : new DefaultPasswordReader();
        load(storeID);
    }
    public interface PasswordReader {
        char[] readPassword() throws IOException;
    }
    private class DefaultPasswordReader implements PasswordReader {
        public char[] readPassword() throws IOException {
            return new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
        }
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
        Security.addProvider( new BouncyCastleProvider() );
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
    @Override public char[] getPassPhraseGetSetEntry() {
        return passPhraseGetSetEntry;
    }
    public char[] getPassPhraseLoadSave() {
        return passPhraseLoadSave;
    }
    @Override public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        System.err.println("Next line will contain the identity identifying the keystore:");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.keyStore.store(baos, this.passPhraseLoadSave);
        System.out.print(new String(baos.toByteArray()));
        System.out.flush();
        System.err.println();
        return baos.toByteArray();
    }
    @Override void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
        try {
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        } catch (KeyStoreException e) {
            setPassWord(true);
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        }
    }
    @Override public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
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
    static KeyStoreContainer getIt(final int slot,
                                   final String libName) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, LoginException {
        AuthProvider provider = getP11AuthProvider(slot, libName);
        final String providerName = provider.getName();
        Security.addProvider(provider);
        final CallbackHandler cbh = new TextCallbackHandler();
        KeyStore.Builder builder = KeyStore.Builder.newInstance("PKCS11", provider,
                                                                new CallbackHandlerProtection(cbh));
        final KeyStore keyStore = builder.getKeyStore();
        return new KeyStoreContainerP11( keyStore, providerName, providerName );
    }
    @Override public byte[] storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.store(null, null);
        return new byte[0];
    }
    @Override void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, null, chain);
    }
    @Override public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
        return this.keyStore.getKey(alias, null);
    }
    @Override public char[] getPassPhraseGetSetEntry() {
        return null;
    }
}
