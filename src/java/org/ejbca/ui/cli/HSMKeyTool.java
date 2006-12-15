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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * @author lars
 * @version $Id: HSMKeyTool.java,v 1.12 2006-12-15 15:09:35 primelars Exp $
 *
 */
public class HSMKeyTool {
    private static String GENERATE_SWITCH = "generate";
    private static String DELETE_SWITCH = "delete";
    private static String TEST_SWITCH = "test";
    private static String CREATE_KEYSTORE_SWITCH = "createkeystore";
    private static String CREATE_KEYSTORE_MODULE_SWITCH = "createkeystoremodule";
    private static String MOVE_SWITCH = "move";
    /**
     * @param args
     */
    public static void main(String[] args) {
        try {
            if ( args.length > 1 && args[1].toLowerCase().trim().equals(GENERATE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <key size> [<key entry name>] [<keystore ID>]");
                else
                    generate(args[2], args[3], Integer.parseInt(args[4].trim()), args.length>5 ? args[5] :"myKey", args.length>6 ? args[6] : null);
            } else if ( args.length > 1 && args[1].toLowerCase().trim().equals(DELETE_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <keystore ID> [<key entry name>]");
                else
                    new KeyStoreContainer(args[3], getProviderName(args[2]), args[4]).delete(args.length>5 ? args[5] : null);
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(TEST_SWITCH)) {
                if ( args.length < 5 )
                    System.err.println(args[0] + " " + args[1] + " <keystore ID> [<# of tests>]");
                else
                    test(args[2], args[3], args[4], args.length>5 ? Integer.parseInt(args[5].trim()) : 1);
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_SWITCH)) {
                new KeyStoreContainer(args[3], getProviderName(args[2]), null).storeKeyStore();
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(CREATE_KEYSTORE_MODULE_SWITCH)) {
                System.setProperty("protect", "module");
                new KeyStoreContainer(args[3], getProviderName(args[2]), null).storeKeyStore();
            } else if( args.length > 1 && args[1].toLowerCase().trim().equals(MOVE_SWITCH)) {
                if ( args.length < 6 )
                    System.err.println(args[0] + " " + args[1] + " <from keystore ID> <to keystore ID>");
                else
                    move(args[2], args[3], args[4], args[5]);
            } else
                System.err.println("Use \"" + args[0]+" "+GENERATE_SWITCH+"\" or \"" +
                                   args[0]+" "+DELETE_SWITCH+"\" or \"" +
                                   args[0]+" "+TEST_SWITCH+"\" or \"" +
                                   args[0]+" "+CREATE_KEYSTORE_SWITCH+"\" or \"" +
                                   args[0]+" "+CREATE_KEYSTORE_MODULE_SWITCH+"\" or \"" +
                                   args[0]+" "+MOVE_SWITCH+"\".");
        } catch (Throwable e) {
            e.printStackTrace(System.err);
        }
    }
    private static class KeyStoreContainer {
        private void setPassWord(boolean isKeystoreException) throws IOException {
            System.err.println((isKeystoreException ? "Setting key entry in keystore" : "Loading keystore")+". Give password of inserted card in slot:");
            char result[] = new BufferedReader(new InputStreamReader(System.in)).readLine().toCharArray();
            if ( isKeystoreException )
                passPhraseGetSetEntry = result;
            else
                passPhraseLoadSave = result;
        }
        private final KeyStore keyStore;
        private char passPhraseLoadSave[] = null;
        private char passPhraseGetSetEntry[] = null;
        private KeyStoreContainer(KeyStore ks) {
            keyStore = ks;
        }
        KeyStoreContainer(final String keyStoreType,
                          final String providerName,
                          final String storeID) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException {
             this( KeyStore.getInstance(keyStoreType, providerName) );
             try {
                 load(storeID);
             } catch( IOException e ) {
                 setPassWord(false);
                 load(storeID);
             }
        }
        private void load(String storeID) throws NoSuchAlgorithmException, CertificateException, IOException {
            keyStore.load(storeID!=null ? new ByteArrayInputStream(storeID.getBytes()):null, passPhraseLoadSave);
        }
        void storeKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
            System.err.println("Next line will contain the identity identifying the keystore:");
            keyStore.store(System.out, passPhraseLoadSave);
            System.out.flush();
            System.err.println();
        }
        KeyStore getKeyStore() {
            return keyStore;
        }
        void setKeyEntry(String alias, Key key, Certificate chain[]) throws IOException, KeyStoreException {
            try {
                keyStore.setKeyEntry(alias, key, passPhraseGetSetEntry, chain);
            } catch (KeyStoreException e) {
                setPassWord(true);
                keyStore.setKeyEntry(alias, key, passPhraseGetSetEntry, chain);
            }
        }
        void deleteAlias(String alias) throws KeyStoreException {
            keyStore.deleteEntry(alias);
            System.err.println("Deleting certificate with alias "+alias+'.');
        }
        void delete(final String alias) throws Exception {
            if ( alias!=null )
                deleteAlias(alias);
            else {
                Enumeration e = keyStore.aliases();
                while( e.hasMoreElements() )
                    deleteAlias( (String)e.nextElement() );
            }
            storeKeyStore();
        }
        Key getKey(String alias) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
            try {
                return keyStore.getKey(alias, passPhraseGetSetEntry);
            } catch (UnrecoverableKeyException e1) {
                setPassWord(true);
                return keyStore.getKey(alias, passPhraseGetSetEntry );
            }
        }
    }
    private static String getProviderName( String className ) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException {
        Provider provider = (Provider)Class.forName(className).getConstructor(new Class[0]).newInstance(new Object[0]);
        Security.addProvider(provider);
        return provider.getName();
    }
    private static X509Certificate getSelfCertificate (String myname,
                                                       long validity,
                                                       String sigAlg,
                                                       KeyPair keyPair,
                                                       String providerName) throws CertificateException, InvalidKeyException,
                                                       SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
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
        return cg.generate(keyPair.getPrivate(), providerName);
    }
    private static KeyPair generate( final String provider,
                                     final String algName,
                                     final int size) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, provider);
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }
    private static void generate(final String providerClassName,
                                 final String keyStoreType,
                                 final int keySize,
                                 final String keyEntryName,
                                 final String storeID) throws Exception {
        // Generate the RSA Keypair
        final String keyAlgName = "RSA";
        final String sigAlgName = "SHA1withRSA";
        final String providerName = getProviderName(providerClassName);
        final KeyPair keyPair = generate(providerName, keyAlgName, keySize);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = getSelfCertificate("CN=some guy, L=around, C=US",
                                      (long)30*24*60*60*365, sigAlgName, keyPair,
                                      providerName);
        System.err.println("Creating certificate with entry "+keyEntryName+" in KeyStore of type "+keyStoreType+" with provider "+providerName+'.');
        KeyStoreContainer ks = new KeyStoreContainer(keyStoreType, providerName, storeID);
        ks.setKeyEntry(keyEntryName, keyPair.getPrivate(), chain);
        ks.storeKeyStore();
    }
    private static void move(final String providerClassName,
                             final String keyStoreType,
                             final String fromID,
                             final String toID) throws IllegalArgumentException, SecurityException, InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException, ClassNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, NoSuchProviderException, IOException, UnrecoverableKeyException {
        String providerName=getProviderName(providerClassName);
        KeyStoreContainer fromKS = new KeyStoreContainer(keyStoreType, providerName, fromID);
        KeyStoreContainer toKS = new KeyStoreContainer(keyStoreType, providerName, toID);
        Enumeration e = fromKS.getKeyStore().aliases();
        while( e.hasMoreElements() ) {
            String alias = (String)e.nextElement();
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
    private static KeyStoreContainer getKeyStoreTest(final String providerName,
                                            final String keyStoreType,
                                            final String storeID) throws Exception {
        KeyStoreContainer keyStore = null;
        while( keyStore==null ) {
            try {
                keyStore = new KeyStoreContainer(keyStoreType, providerName, storeID);
            } catch( Throwable t ) {
                keyStore = null;
                t.printStackTrace(System.err);
                System.err.println("Card set not preloaded. Hit return when error fixed");
                new BufferedReader(new InputStreamReader(System.in)).readLine();
            }
        }
        return keyStore;
    }
    private static Test[] getTests(final KeyStoreContainer keyStore,
                                   final String providerName) throws Exception {
        Enumeration e = keyStore.getKeyStore().aliases();
        Set testSet = new HashSet();
        while( e.hasMoreElements() ) {
            String alias = (String)e.nextElement();
            if ( keyStore.getKeyStore().isKeyEntry(alias) ) {
                PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias);
                testSet.add(new Test(alias,
                                     new KeyPair(keyStore.getKeyStore().getCertificate(alias).getPublicKey(), privateKey),
                                     providerName));
            }
        }
        return (Test[])testSet.toArray(new Test[0]);
    }
    private static class Test {
        final private String alias;
        final private KeyPair keyPair;
        final private String providerName;
        public Test(String a, KeyPair kp, String pn) {
            alias = a;
            keyPair = kp;
            providerName = pn;
        }
        public void doIt(int i) throws Exception {
            signTest(i);
            cryptTest(i);
        }
        private void cryptTest(int i) throws Exception {
            final String testS = "   01 0123456789   02 0123456789   03 0123456789   04 0123456789   05 0123456789   06 0123456789   07 0123456789   08 0123456789   09 0123456789   10 0123456789   11 0123456789   12 0123456789   13 0123456789   14 0123456789   15 0123456789   16 0123456789   17 0123456789   18 0123456789   19 0123456789   20 0123456789   21 0123456789   22 0123456789   23 0123456789   24 0123456789   25 0123456789   26 0123456789   27 0123456789   28 0123456789   29 0123456789   30 0123456789   31 0123456789   32 0123456789   33 0123456789   34 0123456789   35 0123456789   36 0123456789   37 0123456789";
            final int modulusLength = ((RSAKey)keyPair.getPublic()).getModulus().bitLength();
            final int byteLength = (modulusLength+7)/8-11;
            final byte original[] = testS.substring(0, byteLength).getBytes();
            final String pkcs1Padding="RSA/ECB/PKCS1Padding";
//            final String noPadding="RSA/ECB/NoPadding";
            final byte encoded[]; {
                final Cipher cipher = Cipher.getInstance(pkcs1Padding);
                System.out.print("encryption provider: "+cipher.getProvider());
                cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
                encoded = cipher.doFinal(original);
            }
            final byte decoded[]; {
                final Cipher cipher = Cipher.getInstance(pkcs1Padding, providerName);
                System.out.print("; decryption provider: "+cipher.getProvider());
                cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
                decoded = cipher.doFinal(encoded);
            }
            final boolean isSame = Arrays.equals(original, decoded);
            System.out.print("; modulus length: "+modulusLength+"; byte length "+byteLength);
            if (isSame)
                System.out.println(". The docoded byte string is equal to the original!");
            else {
                System.out.println("The original and the decoded byte array differs!");
                System.out.println("Original: \""+new String(original)+'\"');
                System.out.println("Decoded: \""+new String(decoded)+'\"');
            }
        }
        private void signTest(int i) throws Exception {
            final String sigAlgName = "SHA1withRSA";
            final byte signInput[] = "Lillan gick på vägen ut.".getBytes();
            final byte signBA[]; {
                Signature signature = Signature.getInstance(sigAlgName, providerName);
                signature.initSign( keyPair.getPrivate() );
                signature.update( signInput );
                signBA = signature.sign();
            }
            {
                Signature signature = Signature.getInstance(sigAlgName);
                signature.initVerify(keyPair.getPublic());
                signature.update(signInput);
                boolean result = signature.verify(signBA);
                System.out.println("Signature test of key "+alias+
                                   ": signature length " + signBA.length +
                                   "; test nr " + i +
                                   "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                                   "; verifying " + result);
            }
            System.gc();
            System.runFinalization();
        }
    }
    private static void test(final String providerClassName,
                             final String keyStoreType,
                             final String storeID,
                             final int nrOfTests) throws Exception {
        String providerName = getProviderName(providerClassName);
        System.out.println("Test of keystore with ID "+storeID+" of type "+keyStoreType+" with provider "+providerName+'.');
        Test tests[] = null;
        final KeyStoreContainer keyStore = getKeyStoreTest(providerName, keyStoreType, storeID);
        for (int i = 0; i<nrOfTests || nrOfTests<1; i++) {
            try {
                if ( tests==null || nrOfTests==-5 )
                    tests = getTests(keyStore, providerName);
                for( int j = 0; j<tests.length; j++ )
                    tests[j].doIt(i);
            } catch( Throwable t ) {
                tests = null;
                t.printStackTrace(System.err);
            }
        }
    }
}
