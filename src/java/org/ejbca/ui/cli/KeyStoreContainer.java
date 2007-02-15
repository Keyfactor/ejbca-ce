/**
 * 
 */
package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
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
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class KeyStoreContainer {
    private void setPassWord(boolean isKeystoreException) throws IOException {
        System.err.println((isKeystoreException ? "Setting key entry in keystore" : "Loading keystore")+". Give password of inserted card in slot:");
        char result[] = new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
        if ( isKeystoreException )
            this.passPhraseGetSetEntry = result;
        else
            this.passPhraseLoadSave = result;
    }
    private final KeyStore keyStore;
    private final String providerName;
    private final String ecryptProviderName;
    private char passPhraseLoadSave[] = null;
    private char passPhraseGetSetEntry[] = null;
    public KeyStoreContainer(final String keyStoreType,
                             final String providerClassName,
                             final String storeID) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        this( keyStoreType, providerClassName, storeID!=null ? storeID.getBytes():null);
    }
    KeyStoreContainer(final String keyStoreType,
                      final String providerClassName,
                      final byte storeID[]) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Security.addProvider( new BouncyCastleProvider() );
        this.providerName = getProviderName(providerClassName);
        this.ecryptProviderName = getProviderName("com.ncipher.fixup.provider.nCipherRSAPrivateEncrypt");
        System.err.println("Creating KeyStore of type "+keyStoreType+" with provider "+this.providerName+(storeID!=null ? (" with ID "+new String(storeID)) : "")+'.');
        this.keyStore = KeyStore.getInstance(keyStoreType, this.providerName);
         try {
             load(storeID);
         } catch( IOException e ) {
             setPassWord(false);
             load(storeID);
         }
    }
    String getProviderName() {
        return this.providerName;
    }
    private void load(byte storeID[]) throws NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore.load(storeID!=null ? new ByteArrayInputStream(storeID):null, this.passPhraseLoadSave);
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
    public KeyStore getKeyStore() {
        return this.keyStore;
    }
    void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
        try {
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        } catch (KeyStoreException e) {
            setPassWord(true);
            this.keyStore.setKeyEntry(alias, key, this.passPhraseGetSetEntry, chain);
        }
    }
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
    public Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
        try {
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry);
        } catch (UnrecoverableKeyException e1) {
            setPassWord(true);
            return this.keyStore.getKey(alias, this.passPhraseGetSetEntry );
        }
    }
    private String getProviderName( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Object[0]);
        Security.addProvider(provider);
        return provider.getName();
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
    public char[] getPassPhraseGetSetEntry() {
        return passPhraseGetSetEntry;
    }
    static void move(final String providerClassName,
                     final String keyStoreType,
                     final String fromID,
                     final String toID) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException {
        KeyStoreContainer fromKS = new KeyStoreContainer(keyStoreType, providerClassName, fromID);
        KeyStoreContainer toKS = new KeyStoreContainer(keyStoreType, providerClassName, toID);
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
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while( true ) {
                int nextByte = is.read();
                if (nextByte<0)
                    break;
                baos.write(nextByte);
            }
            os.write(doCoding(baos.toByteArray(), alias));
            os.close();
        }
        abstract byte[] doCoding(final byte data[], String alias) throws Exception;
    }
    private class EncryptStream extends CodeStream {
        byte[] doCoding(final byte data[], String alias) throws Exception {    
            final CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            edGen.addKeyTransRecipient( keyStore.getCertificate(alias).getPublicKey(), "hej".getBytes() );
            return edGen.generate(new CMSProcessableByteArray(data), CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC").getEncoded();
        }
    }
    private class DecryptStream extends CodeStream {
        byte[] doCoding(byte[] data, String alias) throws Exception  {
            return ((RecipientInformation)new CMSEnvelopedData(data).getRecipientInfos().getRecipients().iterator().next()).getContent(getKey(alias), KeyStoreContainer.this.ecryptProviderName);
        }
    }
    public void decrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new DecryptStream().code(is, os, alias);
    }
    public void encrypt(InputStream is, OutputStream os, String alias) throws Exception {
        new EncryptStream().code(is, os, alias);
    }
}