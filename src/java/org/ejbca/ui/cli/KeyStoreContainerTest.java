/**
 * 
 */
package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;

class KeyStoreContainerTest {
    final private String alias;
    final private KeyPair keyPair;
    final private String providerName;
    private KeyStoreContainerTest(String a, KeyPair kp, String pn) {
        this.alias = a;
        this.keyPair = kp;
        this.providerName = pn;
    }
    private void doIt(int i) throws Exception {
        signTest(i);
        cryptTest(i);
    }
    private void cryptTest(int i) throws Exception {
        final String testS = "   01 0123456789   02 0123456789   03 0123456789   04 0123456789   05 0123456789   06 0123456789   07 0123456789   08 0123456789   09 0123456789   10 0123456789   11 0123456789   12 0123456789   13 0123456789   14 0123456789   15 0123456789   16 0123456789   17 0123456789   18 0123456789   19 0123456789   20 0123456789   21 0123456789   22 0123456789   23 0123456789   24 0123456789   25 0123456789   26 0123456789   27 0123456789   28 0123456789   29 0123456789   30 0123456789   31 0123456789   32 0123456789   33 0123456789   34 0123456789   35 0123456789   36 0123456789   37 0123456789";
        final int modulusLength = ((RSAKey)this.keyPair.getPublic()).getModulus().bitLength();
        final int byteLength = (modulusLength+7)/8-11;
        final byte original[] = testS.substring(0, byteLength).getBytes();
        final String pkcs1Padding="RSA/ECB/PKCS1Padding";
//      final String noPadding="RSA/ECB/NoPadding";
        final byte encoded[]; {
            final Cipher cipher = Cipher.getInstance(pkcs1Padding);
            System.out.print("encryption provider: "+cipher.getProvider());
            cipher.init(Cipher.ENCRYPT_MODE, this.keyPair.getPublic());
            encoded = cipher.doFinal(original);
        }
        final byte decoded[]; {
            final Cipher cipher = Cipher.getInstance(pkcs1Padding, this.providerName);
            System.out.print("; decryption provider: "+cipher.getProvider());
            cipher.init(Cipher.DECRYPT_MODE, this.keyPair.getPrivate());
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
            Signature signature = Signature.getInstance(sigAlgName, this.providerName);
            signature.initSign( this.keyPair.getPrivate() );
            signature.update( signInput );
            signBA = signature.sign();
        }
        {
            Signature signature = Signature.getInstance(sigAlgName);
            signature.initVerify(this.keyPair.getPublic());
            signature.update(signInput);
            boolean result = signature.verify(signBA);
            System.out.println("Signature test of key "+this.alias+
                               ": signature length " + signBA.length +
                               "; test nr " + i +
                               "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                               "; verifying " + result);
        }
        System.gc();
        System.runFinalization();
    }
    private static KeyStoreContainer getKeyStoreTest(final String providerName,
                                                     final String keyStoreType,
                                                     final String storeID) throws Exception {
        KeyStoreContainer keyStore = null;
        while( keyStore==null ) {
            try {
                keyStore = new KeyStoreContainer(keyStoreType, providerName, storeID);
            } catch( Throwable t ) {
                t.printStackTrace(System.err);
                System.err.println("Card set not preloaded. Hit return when error fixed");
                new BufferedReader(new InputStreamReader(System.in)).readLine();
            }
        }
        return keyStore;
    }
    private static KeyStoreContainerTest[] getTests(final KeyStoreContainer keyStore) throws Exception {
        Enumeration<String> e = keyStore.getKeyStore().aliases();
        Set<KeyStoreContainerTest> testSet = new HashSet<KeyStoreContainerTest>();
        while( e.hasMoreElements() ) {
            String alias = e.nextElement();
            if ( keyStore.getKeyStore().isKeyEntry(alias) ) {
                PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias);
                testSet.add(new KeyStoreContainerTest(alias,
                                                      new KeyPair(keyStore.getKeyStore().getCertificate(alias).getPublicKey(), privateKey),
                                                      keyStore.getProviderName()));
            }
        }
        return testSet.toArray(new KeyStoreContainerTest[0]);
    }
    static void test(final String providerClassName,
                     final String keyStoreType,
                     final String storeID,
                     final int nrOfTests) throws Exception {
        System.out.println("Test of keystore with ID "+storeID+'.');
        KeyStoreContainerTest tests[] = null;
        final KeyStoreContainer keyStore = getKeyStoreTest(providerClassName, keyStoreType, storeID);
        for (int i = 0; i<nrOfTests || nrOfTests<1; i++) {
            try {
                if ( tests==null || nrOfTests==-5 )
                    tests = getTests(keyStore);
                for( int j = 0; j<tests.length; j++ )
                    tests[j].doIt(i);
            } catch( Throwable t ) {
                tests = null;
                t.printStackTrace(System.err);
            }
        }
    }
}