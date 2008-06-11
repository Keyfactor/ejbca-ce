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
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;

import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.keystore.KeyStoreContainer;

/**
 * 
 * @version $Id$
 *
 */
class KeyStoreContainerTest {
    final String alias;
    final KeyPair keyPair;
    final String providerName;
    final int modulusLength;
    final int byteLength;
    KeyStoreContainerTest(String a, KeyPair kp, String pn) {
        this.alias = a;
        this.keyPair = kp;
        this.providerName = pn;
        this.modulusLength = ((RSAKey)keyPair.getPublic()).getModulus().bitLength();
        this.byteLength = (modulusLength+7)/8-11;
    }
    static void test(final String providerClassName,
                     final String encryptProviderClassName,
                     final String keyStoreType,
                     final String storeID,
                     final int nrOfTests,
                     final String alias,
                     final String typeOfOperation) throws Exception {
        if ( alias==null ) {
            startNormal(providerClassName,
                        encryptProviderClassName,
                        keyStoreType,
                        storeID,
                        nrOfTests);
            return;
        }
        startStress(providerClassName,
                    encryptProviderClassName,
                    keyStoreType,
                    storeID,
                    nrOfTests,
                    alias,
                    typeOfOperation==null || typeOfOperation.toLowerCase().indexOf("sign")>=0);
    }
    private static NormalTest[] getTests(final KeyStoreContainer keyStore) throws Exception {
        Enumeration<String> e = keyStore.getKeyStore().aliases();
        Set<NormalTest> testSet = new HashSet<NormalTest>();
        while( e.hasMoreElements() ) {
            String alias = e.nextElement();
            if ( keyStore.getKeyStore().isKeyEntry(alias) ) {
                PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias);
                testSet.add(new NormalTest(alias,
                                           new KeyPair(keyStore.getKeyStore().getCertificate(alias).getPublicKey(), privateKey),
                                           keyStore.getProviderName()));
            }
        }
        return testSet.toArray(new NormalTest[0]);
    }
    private static void startNormal(final String providerClassName,
                                    final String encryptProviderClassName,
                                    final String keyStoreType,
                                    final String storeID,
                                    final int nrOfTests) throws Exception {
        System.out.println("Test of keystore with ID "+storeID+'.');
        NormalTest tests[] = null;
        final KeyStoreContainer keyStore = getKeyStore(providerClassName, encryptProviderClassName,
                                                           keyStoreType, storeID);
        for (int i = 0; i<nrOfTests || nrOfTests<1; i++) {
            try {
                if ( tests==null || nrOfTests==-5 )
                    tests = getTests(keyStore);
                for( int j = 0; j<tests.length; j++ )
                    tests[j].doIt();
            } catch( Throwable t ) {
                tests = null;
                t.printStackTrace(System.err);
            }
        }
    }
    private static void startStress(final String providerClassName,
                                    final String encryptProviderClassName,
                                    final String keyStoreType,
                                    final String storeID,
                                    final int numberOfThreads,
                                    final String alias,
                                    final boolean isSign) throws Exception {
        final KeyStoreContainer keyStore = getKeyStore(providerClassName, encryptProviderClassName,
                                                       keyStoreType, storeID);
        if ( keyStore.getKeyStore().isKeyEntry(alias) ) {
            PrivateKey privateKey = (PrivateKey)keyStore.getKey(alias);
            new KeyStoreContainerTest.StressTest(alias,
                           new KeyPair(keyStore.getKeyStore().getCertificate(alias).getPublicKey(), privateKey),
                           keyStore.getProviderName(),
                           numberOfThreads,
                           -1,
                           isSign);
        } else
            System.out.println("Key alias does not exist.");
    }
    static private KeyStoreContainer getKeyStore(final String providerName,
                                                 final String encryptProviderClassName,
                                                 final String keyStoreType,
                                                 final String storeID) throws Exception {
        KeyStoreContainer keyStore = null;
        while( keyStore==null ) {
            try {
                keyStore = KeyStoreContainer.getInstance(keyStoreType, providerName,
                                                   encryptProviderClassName, storeID, null);
            } catch( Throwable t ) {
                t.printStackTrace(System.err);
                System.err.println("Not possible to load keys. Maybe a smart card should be inserted or maybe you just typed the wrong PIN. Press enter when the problem is fixed.");
                new BufferedReader(new InputStreamReader(System.in)).readLine();
            }
        }
        return keyStore;
    }
    private interface Test {
        void prepare() throws Exception;
        void doOperation() throws Exception;
        boolean verify() throws Exception;
        void printInfo(PrintStream ps);
        String getOperation();
    }
    class Crypto implements Test {
        final private String testS = "   01 0123456789   02 0123456789   03 0123456789   04 0123456789   05 0123456789   06 0123456789   07 0123456789   08 0123456789   09 0123456789   10 0123456789   11 0123456789   12 0123456789   13 0123456789   14 0123456789   15 0123456789   16 0123456789   17 0123456789   18 0123456789   19 0123456789   20 0123456789   21 0123456789   22 0123456789   23 0123456789   24 0123456789   25 0123456789   26 0123456789   27 0123456789   28 0123456789   29 0123456789   30 0123456789   31 0123456789   32 0123456789   33 0123456789   34 0123456789   35 0123456789   36 0123456789   37 0123456789";
        final private byte original[] = testS.substring(0, byteLength).getBytes();
        final private String pkcs1Padding="RSA/ECB/PKCS1Padding";
//      final String noPadding="RSA/ECB/NoPadding";
        private byte encoded[];
        private byte decoded[];
        private Cipher cipherEnCryption;
        private Cipher cipherDeCryption;
        private boolean result;
        public void prepare() throws Exception {
            cipherEnCryption = Cipher.getInstance(pkcs1Padding);
            cipherEnCryption.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            encoded = cipherEnCryption.doFinal(original);
            cipherDeCryption = Cipher.getInstance(pkcs1Padding, providerName);
            cipherDeCryption.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        }
        public void doOperation() throws Exception {
            decoded = cipherDeCryption.doFinal(encoded);
        }
        public boolean verify() {
            result = Arrays.equals(original, decoded);
            return result;
        }
        public void printInfo(PrintStream ps) {
            ps.print("encryption provider: "+cipherEnCryption!=null ? cipherEnCryption.getProvider() : "not initialized");
            ps.print("; decryption provider: "+cipherDeCryption!=null ? cipherDeCryption.getProvider() : "not initialized");
            ps.print("; modulus length: "+modulusLength+"; byte length "+byteLength);
            if ( result ) {
                ps.println(". The docoded byte string is equal to the original!");
            } else {
                ps.println("The original and the decoded byte array differs!");
                ps.println("Original: \""+new String(original)+'\"');
                ps.println("Decoded: \""+new String(decoded)+'\"');
            }
        }
        public String getOperation() {
            return "crypto";
        }
    }
    class Sign implements Test {
        private final String sigAlgName = "SHA1withRSA";
        private final byte signInput[] = "Lillan gick på vägen ut.".getBytes();
        private byte signBA[];
        private Signature signature;
        private boolean result;
        public void prepare() throws Exception {
            signature = Signature.getInstance(sigAlgName, providerName);
            signature.initSign( keyPair.getPrivate() );
            signature.update( signInput );
        }
        public void doOperation() throws Exception {
            signBA = signature.sign();
        }
        public boolean verify() throws Exception {

            Signature verifySignature = Signature.getInstance(sigAlgName);
            verifySignature.initVerify(keyPair.getPublic());
            verifySignature.update(signInput);
            result = verifySignature.verify(signBA);
            return result;
        }
        public void printInfo(PrintStream ps) {
            ps.println("Signature test of key "+alias+
                       ": signature length " + signBA.length +
                       "; first byte " + Integer.toHexString(0xff&signBA[0]) +
                       "; verifying " + result);
        }
        public String getOperation() {
            return "sign";
        }
    }
    static private class StressTest extends KeyStoreContainerTest {
        final PerformanceTest performanceTest;
        StressTest( final String alias,
                    final KeyPair keyPair,
                    final String providerName,
                    final int numberOfThreads,
                    final int waitTime,
                    final boolean isSignTest) throws Exception {
            super(alias, keyPair, providerName);
            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(isSignTest), numberOfThreads, waitTime, System.out);
        }
        private class Prepare implements Command {
            final private Test test;
            Prepare(Test _test) {
                this.test = _test;
            }
            public boolean doIt() throws Exception {
                test.prepare();
                return true;
            }
            public String getJobTimeDescription() {
                return test.getOperation() + " preparation";
            }
        }
        private class DoOperation implements Command {
            final private Test test;
            DoOperation(Test _test) {
                this.test = _test;
            }
            public boolean doIt() throws Exception {
                test.doOperation();
                return true;
            }
            public String getJobTimeDescription() {
                return test.getOperation() + " operation";
            }
        }
        private class Verify implements Command {
            final private Test test;
            Verify(Test _test) {
                this.test = _test;
            }
            public boolean doIt() throws Exception {
                final boolean isOK = test.verify();
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                test.printInfo(new PrintStream(baos,true));
                if ( isOK )
                    performanceTest.getLog().info(baos.toString());
                else
                    performanceTest.getLog().error(baos.toString());
                return isOK;
            }
            public String getJobTimeDescription() {
                return test.getOperation() + " verify";
            }
        }
        private class MyCommandFactory implements CommandFactory {
            private final boolean isSignTest;
            MyCommandFactory(boolean _isSignTest) {
                super();
                this.isSignTest = _isSignTest;
            }
            public Command[] getCommands() throws Exception {
                final Test test = isSignTest ? new Sign() : new Crypto();
                return new Command[]{new Prepare(test), new DoOperation(test), new Verify(test)};
            }
        }
    }
    static private class NormalTest extends KeyStoreContainerTest {
        long totalSignTime = 0;
        long totalDecryptTime = 0;
        int nrOfTests = 0;
        NormalTest(String alias, KeyPair keyPair, String providerName) {
            super(alias, keyPair, providerName);
        }
        private long test(Test test) throws Exception {
            test.prepare();
            final long startTime = System.nanoTime();
            test.doOperation();
            final long totalTime = System.nanoTime()-startTime;
            test.verify();
            test.printInfo(System.out);
            return totalTime;
        }
        void doIt() throws Exception {
            totalDecryptTime += test(new Crypto());
            totalSignTime += test(new Sign());
            nrOfTests++;
            final long nanoNumber = nrOfTests*(long)1000000000;
            System.out.print(alias+" key statistics. Signings per second: ");
            System.out.print(""+(nanoNumber+totalSignTime/2)/totalSignTime+" Decryptions per second: ");
            System.out.println(""+(nanoNumber+totalDecryptTime/2)/totalDecryptTime);
        }

    }
}