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
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.token.p11.PKCS11Utils;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.ISignOperation;
import org.cesecore.keys.util.SignWithWorkingAlgorithm;
import org.cesecore.keys.util.TaskWithSigningException;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.keystore.KeyStoreToolsFactory;

/**
 *
 * @version $Id$
 *
 */
class KeyStoreContainerTest {
    final String alias;
    final KeyPair keyPair;
    final protected String providerName;
    final private static PrintStream termOut = System.out;
    final private static PrintStream termErr = System.err;
    final private static InputStream termIn = System.in;
    final static private Logger log = Logger.getLogger(KeyStoreContainerTest.class);
    KeyStoreContainerTest(String a, KeyPair kp, String pn) {
        this.alias = a;
        this.keyPair = kp;
        this.providerName = pn;
    }
    static void test(
            final String p11moduleName,
            final String storeID,
            final Pkcs11SlotLabelType slotLabelType,
            final int nrOfThreads,
            final int nrOfTests,
            final String alias,
            final String typeOfOperation,
            final ProtectionParameter protectionParameter) throws Exception {
        if ( alias==null ) {
            startNormal(
                    p11moduleName,
                    storeID,
                    slotLabelType,
                    nrOfTests>0 ? nrOfTests : nrOfThreads,
                    protectionParameter);
        } else {
            startStress(
                    p11moduleName,
                    storeID,
                    slotLabelType,
                    nrOfThreads,
                    nrOfTests,
                    alias,
                    typeOfOperation==null || typeOfOperation.toLowerCase().indexOf("sign")>=0,
                    protectionParameter);
        }
    }
    private static NormalTest[] getTests(final KeyStoreTools keyStore) throws Exception {
        Enumeration<String> e = keyStore.getKeyStore().aliases();
        Set<NormalTest> testSet = new HashSet<>();
        while( e.hasMoreElements() ) {
            String alias = e.nextElement();
            if ( !keyStore.getKeyStore().isKeyEntry(alias) ) {
                continue;
            }
            try {
                final PrivateKey privateKey = (PrivateKey)keyStore.getKeyStore().getKey(alias, null);
                final Certificate cert = keyStore.getKeyStore().getCertificate(alias);
                if (cert != null) {
                    testSet.add(new NormalTest(alias,
                            new KeyPair(cert.getPublicKey(), privateKey),
                            keyStore.getProviderName()));
                } else {
                    termOut.println("Not testing keys with alias "+alias+". No certificate exists.");
                }
            } catch (ClassCastException ce) {
                termOut.println(String.format("Not testing keys with alias %s. Not a private key. Exception: %s", alias, ce.getMessage()));
            } catch (KeyStoreException | ProviderException ce) {
                termOut.println(String.format("Not testing keys with alias %s. KeyStoreException getting key: %s", alias, ce.getMessage()));
            }
        }
        return testSet.toArray(new NormalTest[testSet.size()]);
    }
    private static void startNormal(
            final String p11moduleName,
            final String storeID,
            final Pkcs11SlotLabelType slotLabelType,
            final int nrOfTests,
            final ProtectionParameter protectionParameter) throws Exception {
        termOut.println("Test of keystore with ID "+storeID+'.');
        NormalTest tests[] = null;
        final KeyStoreTools keyStore = getKeyStoreTools(
                p11moduleName, storeID, slotLabelType, protectionParameter);
        for (int i = 0; i<nrOfTests || nrOfTests<1; i++) {
            try {
                if ( tests==null || nrOfTests==-5 ) {
                    tests = getTests(keyStore);
                }
                for( int j = 0; j<tests.length; j++ ) {
                    termOut.println();
                    tests[j].doIt();
                }
            } catch( Throwable t ) { // NOPMD: dealing with HSMs we really want to catch all
                tests = null;
                log.error("Error running test.", t);
            }
        }
    }
    private static void startStress(
                                    final String p11moduleName,
                                    final String storeID,
                                    final Pkcs11SlotLabelType slotLabelType,
                                    final int numberOfThreads,
                                    final int nrOfTests,
                                    final String alias,
                                    final boolean isSign,
                                    final ProtectionParameter protectionParameter) throws Exception {
        final KeyStoreTools keyStore = getKeyStoreTools(
                p11moduleName, storeID, slotLabelType, protectionParameter);
        if ( !keyStore.getKeyStore().isKeyEntry(alias) ) {
            termErr.println("Key alias does not exist.");
            return;
        }
        PrivateKey privateKey = (PrivateKey)keyStore.getKeyStore().getKey(alias, null);
        StressTest.execute(
                alias,
                new KeyPair(keyStore.getKeyStore().getCertificate(alias).getPublicKey(), privateKey),
                keyStore.getProviderName(),
                numberOfThreads,
                nrOfTests,
                -1,
                isSign);
    }
    static private KeyStoreTools getKeyStoreTools(
            final String p11moduleName,
            final String storeID,
            final Pkcs11SlotLabelType slotLabelType,
            final ProtectionParameter protectionParameter) throws Exception {
        KeyStoreTools keyStoreTools = null;
        while( keyStoreTools==null ) {
            try {
                keyStoreTools = KeyStoreToolsFactory.getInstance(
                        p11moduleName, storeID, slotLabelType, null, protectionParameter);
            } catch( Throwable t ) { // NOPMD: dealing with HSMs we really want to catch all
                log.error("Not possible to load keys.", t);
                termErr.println("Not possible to load keys. Maybe a smart card should be inserted or maybe you just typed the wrong PIN. Press enter when the problem is fixed or 'x' enter to quit.");
                final int character = termIn.read();
                if( character=='x' || character== 'X') {
                    System.exit(-1);
                }
            }
        }
        return keyStoreTools;
    }
    private interface Test {
        void prepare() throws Exception;
        void doOperation() throws Exception;
        boolean verify() throws Exception;
        void printInfo(PrintStream ps);
        String getOperation();
    }
    class CryptoNotAvailableForThisAlgorithm extends Exception {
        private static final long serialVersionUID = 0L;
        CryptoNotAvailableForThisAlgorithm() {
            super("");
        }
    }
    class Crypto implements Test {
        final int modulusLength;
        final int byteLength;
        final private String testS = "   01 0123456789   02 0123456789   03 0123456789   04 0123456789   05 0123456789   06 0123456789   07 0123456789   08 0123456789   09 0123456789   10 0123456789   11 0123456789   12 0123456789   13 0123456789   14 0123456789   15 0123456789   16 0123456789   17 0123456789   18 0123456789   19 0123456789   20 0123456789   21 0123456789   22 0123456789   23 0123456789   24 0123456789   25 0123456789   26 0123456789   27 0123456789   28 0123456789   29 0123456789   30 0123456789   31 0123456789   32 0123456789   33 0123456789   34 0123456789   35 0123456789   36 0123456789   37 0123456789";
        final private byte original[];
        final private String pkcs1Padding="RSA/ECB/PKCS1Padding";
//      final String noPadding="RSA/ECB/NoPadding";
        private byte encoded[];
        private byte decoded[];
        private Cipher cipherEnCryption;
        private Cipher cipherDeCryption;
        private boolean result;
        Crypto() throws CryptoNotAvailableForThisAlgorithm {
            if ( ! (KeyStoreContainerTest.this.keyPair.getPublic() instanceof RSAKey) ) {
                throw new CryptoNotAvailableForThisAlgorithm();
            }
            this.modulusLength = ((RSAKey)KeyStoreContainerTest.this.keyPair.getPublic()).getModulus().bitLength();
            this.byteLength = (this.modulusLength+7)/8-11;
            this.original = this.testS.substring(0, this.byteLength).getBytes();
        }
        @Override
        public void prepare() throws Exception {
            this.cipherEnCryption = Cipher.getInstance(this.pkcs1Padding);
            this.cipherEnCryption.init(Cipher.ENCRYPT_MODE, KeyStoreContainerTest.this.keyPair.getPublic());
            this.encoded = this.cipherEnCryption.doFinal(this.original);
            this.cipherDeCryption = Cipher.getInstance(this.pkcs1Padding, KeyStoreContainerTest.this.providerName);
            this.cipherDeCryption.init(Cipher.DECRYPT_MODE, KeyStoreContainerTest.this.keyPair.getPrivate());
        }
        @Override
        public void doOperation() throws Exception {
            this.decoded = this.cipherDeCryption.doFinal(this.encoded);
        }
        @Override
        public boolean verify() {
            this.result = Arrays.equals(this.original, this.decoded);
            return this.result;
        }
        @Override
        public void printInfo(PrintStream ps) {
            ps.print("encryption provider: "+(this.cipherEnCryption!=null ? this.cipherEnCryption.getProvider() : "not initialized"));
            ps.print("; decryption provider: "+(this.cipherDeCryption!=null ? this.cipherDeCryption.getProvider() : "not initialized"));
            ps.print("; modulus length: "+this.modulusLength+"; byte length "+this.byteLength);
            if ( this.result ) {
                ps.println(". The decoded byte string is equal to the original!");
            } else {
                ps.println("The original and the decoded byte array differs!");
                ps.println("Original: \""+new String(this.original)+'\"');
                ps.println("Decoded: \""+new String(this.decoded)+'\"');
            }
        }
        @Override
        public String getOperation() {
            return "crypto";
        }
    }

    static private class TestData {
        private static final byte[] STATIC_TEST_DATA = "Lillan gick on the roaden ut.".getBytes();
        private static final String FILENAME = "./testData";

        private static boolean isFileNotAvailable = false;
        private static boolean isFileTested = false;

        private static InputStream getInput() {
            if ( isFileTested && isFileNotAvailable ) {
                return null;
            }
            isFileTested = true;
            try {
                final InputStream is = new FileInputStream(FILENAME);
                isFileNotAvailable = false;
                return is;
            } catch (FileNotFoundException e) {
                // Apparently it never existed or has been removed during the test
                isFileNotAvailable = true;
                return null;
            }
        }
        /**
         * Load the provided signature with test data from either a file or a hard coded short String.
         * @param signature
         * @throws Exception
         */
        @SuppressWarnings("synthetic-access")
        public static void updateWithTestData(final Signature signature) throws Exception {
            try (final InputStream is = getInput() ) {
                log.trace("Start updating ...");
                if (is==null) {
                    // Update the signer with hard coded test data, since no file was available
                    signature.update(Arrays.copyOf(STATIC_TEST_DATA, STATIC_TEST_DATA.length));
                    return;
                }
                // Load the found file with test data into the signer
                final byte buffer[] = new byte[16*1024];
                while ( true ) {
                    final int length = is.read(buffer);
                    if ( length<0 ) {
                        break;
                    }
                    log.trace("Updating ...");
                    signature.update(buffer, 0, length);
                }
            }
        }
    }

    private class SignOperation implements ISignOperation {
        private String workingAlgorithm;
        @Override
        public void taskWithSigning(String signAlgorithm, Provider provider) throws TaskWithSigningException {
            final Signature sign;
            try {
                sign = Signature.getInstance(signAlgorithm, provider);
                sign.initSign(KeyStoreContainerTest.this.keyPair.getPrivate());
                sign.update("Kort string att signera!".getBytes());
                sign.sign();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new TaskWithSigningException("Signing failed", e);
            }
            this.workingAlgorithm = signAlgorithm;
        }
        public String getWorkingAlgorithm() {
            return this.workingAlgorithm;
        }
    }
    class Sign implements Test {
        private final String sigAlgName;
        private byte signBA[];
        private Signature signature;
        private boolean result;
        @SuppressWarnings("synthetic-access")
        Sign() throws NoSuchProviderException, GeneralSecurityException, TaskWithSigningException {
            final SignOperation operation = new SignOperation();
            // Candidate algorithms. The first working one will be selected by SignWithWorkingAlgorithm
            final List<String> availableAlogorithms = AlgorithmTools.getSignatureAlgorithms(KeyStoreContainerTest.this.keyPair.getPublic());
            SignWithWorkingAlgorithm.doSignTask(availableAlogorithms, KeyStoreContainerTest.this.providerName, operation);
            this.sigAlgName = operation.getWorkingAlgorithm();
            if ( this.sigAlgName==null ) {
                throw new GeneralSecurityException(
                        String.format(
                                "Not possible to find working signing algorithm for key with alias '%s' using the provider '%s'.",
                                KeyStoreContainerTest.this.alias,
                                KeyStoreContainerTest.this.providerName));
            }
        }
        @Override
        public void prepare() throws Exception {
            this.signature = Signature.getInstance(this.sigAlgName, KeyStoreContainerTest.this.providerName);
            this.signature.initSign( KeyStoreContainerTest.this.keyPair.getPrivate() );
            TestData.updateWithTestData(this.signature);
        }
        @Override
        public void doOperation() throws Exception {
            this.signBA = this.signature.sign();
        }
        @Override
        public boolean verify() throws Exception {

            final Signature verifySignature = Signature.getInstance(this.sigAlgName);
            verifySignature.initVerify(KeyStoreContainerTest.this.keyPair.getPublic());
            TestData.updateWithTestData(verifySignature);
            this.result = verifySignature.verify(this.signBA);
            return this.result;
        }
        @Override
        public void printInfo(PrintStream ps) {
            ps.println("Signature test of key "+KeyStoreContainerTest.this.alias+
                       ": signature length " + this.signBA.length +
                       "; first byte " + Integer.toHexString(0xff&this.signBA[0]) +
                       "; verifying " + this.result);
        }
        @Override
        public String getOperation() {
            return "sign";
        }
    }
    static private class StressTest extends KeyStoreContainerTest {
        final private PerformanceTest performanceTest;
        private StressTest(
                final String alias,
                final KeyPair keyPair,
                final String providerName) {
            super(alias, keyPair, providerName);
            this.performanceTest = new PerformanceTest();
        }
        static void execute(
                final String alias,
                final KeyPair keyPair,
                final String providerName,
                final int numberOfThreads,
                final int nrOfTests,
                final int waitTime,
                final boolean isSignTest) throws Exception {
            final StressTest test = new StressTest(alias, keyPair, providerName);
            test.execute(numberOfThreads, nrOfTests, waitTime, isSignTest);
        }
        @SuppressWarnings("synthetic-access")
        private void execute(
                final int numberOfThreads,
                final int nrOfTests,
                final int waitTime,
                final boolean isSignTest
                ) throws Exception {
            this.performanceTest.execute(new MyCommandFactory(isSignTest), numberOfThreads, nrOfTests, waitTime, termOut);
        }
        private class Prepare implements Command {
            final private Test test;
            Prepare(Test _test) {
                this.test = _test;
            }
            @Override
            public boolean doIt() throws Exception {
                this.test.prepare();
                return true;
            }
            @Override
            public String getJobTimeDescription() {
                return this.test.getOperation() + " preparation";
            }
        }
        private class DoOperation implements Command {
            final private Test test;
            DoOperation(Test _test) {
                this.test = _test;
            }
            @Override
            public boolean doIt() throws Exception {
                this.test.doOperation();
                return true;
            }
            @Override
            public String getJobTimeDescription() {
                return this.test.getOperation() + " operation";
            }
        }
        private class Verify implements Command {
            final private Test test;
            Verify(Test _test) {
                this.test = _test;
            }
            @SuppressWarnings("synthetic-access")
            @Override
            public boolean doIt() throws Exception {
                final boolean isOK = this.test.verify();
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                this.test.printInfo(new PrintStream(baos,true));
                if ( isOK ) {
                    StressTest.this.performanceTest.getLog().info(baos.toString());
                } else {
                    StressTest.this.performanceTest.getLog().error(baos.toString());
                }
                return isOK;
            }
            @Override
            public String getJobTimeDescription() {
                return this.test.getOperation() + " verify";
            }
        }
        private class MyCommandFactory implements CommandFactory {
            private final boolean isSignTest;
            MyCommandFactory(boolean _isSignTest) {
                super();
                this.isSignTest = _isSignTest;
            }
            @Override
            public Command[] getCommands() throws Exception {
                final Test test = this.isSignTest ? new Sign() : new Crypto();
                return new Command[]{new Prepare(test), new DoOperation(test), new Verify(test)};
            }
        }
    }
    @SuppressWarnings("synthetic-access")
    static private class NormalTest extends KeyStoreContainerTest {
        long totalSignTime = 0;
        long totalDecryptTime = 0;
        int nrOfTests = 0;
        NormalTest(String alias, KeyPair keyPair, String providerName) {
            super(alias, keyPair, providerName);
        }
        private static long test(Test test) throws Exception { // NOPMD: this is not a JUnit test
            test.prepare();
            final long startTime = System.nanoTime();
            test.doOperation();
            final long totalTime = System.nanoTime()-startTime;
            test.verify();
            test.printInfo(termOut);
            return totalTime;
        }
        void doIt() {
            final String CSI = "\u001B";
            termOut.println(CSI+"[1;4mTesting of key: "+this.alias+CSI+"[0m");
            if ( KeyTools.isPrivateKeyExtractable(this.keyPair.getPrivate()) ) {
                termOut.println(CSI+"[1;5;31mPrivate key extractable. Do not ever use this key. Delete it."+CSI+"[0m");
            } else {
                termOut.println("Private part:"); termOut.println(this.keyPair.getPrivate());
            }
            KeyTools.printPublicKeyInfo(this.keyPair.getPublic(), termOut);
            {
                final StringBuilder sb = new StringBuilder("Security related private key attributes:  ");
                PKCS11Utils.getInstance().securityInfo(this.keyPair.getPrivate(), this.providerName, sb);
                termOut.println(sb.toString());
            }
            boolean isCryptoAvailable = true;
            try {
                this.totalDecryptTime += test(new Crypto());
            } catch(CryptoNotAvailableForThisAlgorithm e ) {
                isCryptoAvailable = false;
            } catch( Exception e) {
                this.totalDecryptTime = -1;
                e.printStackTrace(termOut);
            }
            try {
                this.totalSignTime += test(new Sign());
            } catch (Exception e) {
                this.totalSignTime = -1;
                e.printStackTrace(termOut);
            }
            this.nrOfTests++;
            final long nanoNumber = this.nrOfTests*(long)1000000000;
            if ( this.totalSignTime < 0) {
                termOut.println("Signing not possible with this key. See exception.");
            } else {
                termOut.println("Signings per second: "+(nanoNumber+this.totalSignTime/2)/this.totalSignTime);
            }
            if ( isCryptoAvailable ) {
                if ( this.totalDecryptTime < 0) {
                    termOut.println("Crypto not possible with this key. See exception");
                } else {
                    termOut.println("Decryptions per second: "+(nanoNumber+this.totalDecryptTime/2)/this.totalDecryptTime);
                }
            } else {
                termOut.println("No crypto available for this key.");
            }
        }

    }
}
