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

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.keys.token.p11.Pkcs11SlotLabelType;
import org.cesecore.keys.util.KeyStoreTools;
import org.cesecore.util.CertTools;
import org.ejbca.util.keystore.KeyStoreToolsFactory;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.ExpectedSystemExit;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Run tests with ClientToolBax command HSMKeyTool
 * @version Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PKCS11HSMKeyToolCommandTest {

    private final HSMKeyTool command = new HSMKeyTool();

    private static final String PKCS11_LIBRARY = SystemTestsConfiguration.getPkcs11Library(null);
    private static final String TOKEN_PIN = new String(SystemTestsConfiguration.getPkcs11SlotPin(null));
    private static final String SLOT_ID = SystemTestsConfiguration.getPkcs11TokenNumber();
    private static final String SLOT_INDEX = SystemTestsConfiguration.getPkcs11TokenIndex();
    private static final String SLOT_LABEL = SystemTestsConfiguration.getPkcs11TokenLabel();
    private static final String SLOT2_ID = SystemTestsConfiguration.getPkcs11Token2Number();
    private static final String SLOT2_INDEX = SystemTestsConfiguration.getPkcs11Token2Index();
    private static final String SLOT2_LABEL = SystemTestsConfiguration.getPkcs11Token2Label();


    private static final InputStream originalSystemIn = System.in;
    private static final ByteArrayOutputStream errStream = new ByteArrayOutputStream();
    private static final PrintStream originalSystemError = System.err;

    private static String CONTENT = "Twas brillig, and the slithy toves \n" +
            "Did gyre and gimble in the wabe: \n" +
            "All mimsy were the borogoves, \n" +
            "And the mome raths outgrabe. ";

    private static String[] aliases = new String[]{"rsa1", "rsa2", "kot", "ecc", "dsa", "TestRootOld", "TestRootNew"};

    private static File inFile;
    private static File certFile;

    @Rule
    public final ExpectedSystemExit exit = ExpectedSystemExit.none();
    @ClassRule
    public static TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void setUp() {
        String data = "xx";
        final ByteArrayInputStream inStream = new ByteArrayInputStream(data.getBytes());
        System.setIn(inStream);
        System.setErr(new PrintStream(errStream));
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        System.setIn(originalSystemIn);
        // Restore original System.err
        System.setErr(originalSystemError);
        System.err.println(errStream.toString());
        errStream.reset();
        System.out.println("CLEAN UP!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(TOKEN_PIN.toCharArray());
        ;
        final KeyStoreTools store1 = KeyStoreToolsFactory.getInstance(PKCS11_LIBRARY, SLOT_LABEL,
                Pkcs11SlotLabelType.SLOT_LABEL, null, protectionParameter, "batch-" + new Date().getTime());
        for (String alias : aliases) {
            store1.getKeyStore().deleteEntry(alias);
        }
        final KeyStoreTools store2 = KeyStoreToolsFactory.getInstance(PKCS11_LIBRARY, SLOT2_LABEL,
                Pkcs11SlotLabelType.SLOT_LABEL, null, protectionParameter, "batch-" + new Date().getTime());
        for (String alias : aliases) {
            store2.getKeyStore().deleteEntry(alias);
        }
    }

    @Test
    public void testA1Token1WithIx() {
        //no exit, because no alias.
        //PKCS11HSMKeyTool test ${p11m} i${ix_1} -password ${userPass_2}
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT_INDEX, "-password", TOKEN_PIN};
        command.execute(args);
    }

    @Test
    public void testA2GenerateKeyOnToken1WithCfgFile() throws IOException {
        String slotConfigs = "name=PKCS11HSMKeyToolCommandTest\n" +
                "library=" + PKCS11_LIBRARY + "\n" +
                "slot=" + SLOT_ID + "\n" +
                "attributes(*, CKO_PUBLIC_KEY, *) = {\n" +
                "  CKA_TOKEN = false\n" +
                "  CKA_ENCRYPT = true\n" +
                "  CKA_VERIFY = true\n" +
                "  CKA_WRAP = true\n" +
                "}\n" +
                "attributes(*, CKO_PRIVATE_KEY, *) = {\n" +
                "  CKA_TOKEN = true\n" +
                "  CKA_PRIVATE = true\n" +
                "  CKA_SENSITIVE = false\n" +
                "  CKA_EXTRACTABLE = true\n" +
                "  CKA_DECRYPT = true\n" +
                "  CKA_SIGN = true\n" +
                "  CKA_UNWRAP = true\n" +
                "}\n" +
                "disabledMechanisms = {\n" +
                "  CKM_SHA1_RSA_PKCS\n" +
                "  CKM_SHA256_RSA_PKCS\n" +
                "  CKM_SHA384_RSA_PKCS\n" +
                "  CKM_SHA512_RSA_PKCS\n" +
                "  CKM_MD2_RSA_PKCS\n" +
                "  CKM_MD5_RSA_PKCS\n" +
                "  CKM_DSA_SHA1\n" +
                "  CKM_ECDSA_SHA1\n" +
                "}\n";
        File slotConfigFile = folder.newFile("slotID.cfg");
        try (FileOutputStream fileOutputStream = new FileOutputStream(slotConfigFile)) {
            fileOutputStream.write(slotConfigs.getBytes());
        }

        //PKCS11HSMKeyTool generate ./slotID.cfg 2048 rsa2 -password ${userPass_1}
        String[] args = new String[]{"PKCS11HSMKeyTool", "generate", slotConfigFile.getAbsolutePath(),
                "2048", aliases[1], "-password", TOKEN_PIN};
        command.execute(args);
    }

    @Test
    public void testA3CfgKeyRsa2OnToken1WithId() {
        //uses alias, so uses StressTest->Perfomance test exits, status= number of failures.
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} ${id_1} 10:35 rsa2
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT_ID, numberOfThreads + ":" + numberOfTests, aliases[1]};
        command.execute(args);
    }

    @Test
    public void testA4MoveAllKeysFromToken1ToToken2() {
        //PKCS11HSMKeyTool move ./p11m.so ${label_1} ${label_2}
        String[] args = new String[]{"PKCS11HSMKeyTool", "move", PKCS11_LIBRARY,
                SLOT_LABEL, SLOT2_LABEL};
        command.execute(args);
    }

    @Test
    public void testA5Rsa2NowHasBeenMovedToToken2() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_2} 10:35 rsa2
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT2_LABEL, numberOfThreads + ":" + numberOfTests, aliases[1]};
        command.execute(args);
    }

    @Test
    public void testA6RenameKeyWithAliasRsa2ToRsa3OnToken2() {
        //PKCS11HSMKeyTool rename ./p11m.so SLOT_LABEL:${label_2} rsa2 rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "rename", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT2_LABEL, aliases[1], aliases[2]};
        command.execute(args);
    }

    @Test
    public void testA7Rsa3IsNowExistingOnToken2() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} i${ix_2} 10:35 rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT2_ID, numberOfThreads + ":" + numberOfTests, aliases[2]};
        command.execute(args);
    }

    @Test
    public void testA8NoKeyWithAliasRsa2IsExistingOnToken2() {
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_2} 10:35 rsa2
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT2_LABEL, numberOfThreads + ":" + numberOfTests, aliases[1]};
        command.execute(args);

        final String consoleOutput = errStream.toString();
        String message = "Key alias " + aliases[1] + " does not exist";
        assertTrue("System.err should contain: " + message, consoleOutput.contains(message));
    }

    @Test
    public void testA9BatchGenerationOfKeysOnToken1() throws IOException {
        String batchGenerateProperties = aliases[3] + " secp192r1\n" +
                aliases[4] + " DSA1024\n" +
                aliases[0] + " 2048";
        File batchFile = folder.newFile("batchGenerate.txt");
        try (FileOutputStream fileOutputStream = new FileOutputStream(batchFile)) {
            fileOutputStream.write(batchGenerateProperties.getBytes());
        }
        //PKCS11HSMKeyTool batchgenerate ${p11m} ${batchGenerateFile} TOKEN_LABEL:${label_1}
        String[] args = new String[]{"PKCS11HSMKeyTool", "batchgenerate", PKCS11_LIBRARY, batchFile.getCanonicalPath(),
                "TOKEN_LABEL:" + SLOT_LABEL, "-password", TOKEN_PIN};
        command.execute(args);
    }

    @Test
    public void testB10EccOnToken1() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_1} 10:35 ecc
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, numberOfThreads + ":" + numberOfTests, aliases[3]};
        command.execute(args);
    }

    @Test
    public void testB11DsaOnToken1() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_1} 10:35 dsa
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, numberOfThreads + ":" + numberOfTests, aliases[4]};
        command.execute(args);
    }

    @Test
    public void testB12LinkcertForEntryTestRootNewFromEntryTestRootOld() throws Exception {
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(TOKEN_PIN.toCharArray());
        ;
        final KeyStoreTools store = KeyStoreToolsFactory.getInstance(PKCS11_LIBRARY, SLOT_LABEL,
                Pkcs11SlotLabelType.SLOT_LABEL, null, protectionParameter, "batch-" + new Date().getTime());

        String oldName = aliases[5];
        final X509Certificate[] oldChain = generateKeyEntry(store, oldName, protectionParameter);
        String oldFileName = oldName + ".der";
        File oldRootCertFile = folder.newFile(oldFileName);
        try (final OutputStream os = new FileOutputStream(oldRootCertFile.getCanonicalPath())) {
            writeChainToStream(os, oldChain);
        }

        String newName = aliases[6];
        final X509Certificate[] newChain = generateKeyEntry(store, newName, protectionParameter);
        String newFileName = newName + ".der";
        File newRootCertFile = folder.newFile(newFileName);
        try (final OutputStream os = new FileOutputStream(newRootCertFile.getCanonicalPath())) {
            writeChainToStream(os, newChain);
        }

        String linkedFileName = "linkCert.der";
        File linkedRootCertFile = folder.newFile(linkedFileName);
        //PKCS11HSMKeyTool linkcert ${p11m} TOKEN_LABEL:${label_1} TestRootOld.der TestRootNew.der linkCert.der TestRootOld
        String[] args = new String[]{"PKCS11HSMKeyTool", "linkcert", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, oldRootCertFile.getCanonicalPath(), newRootCertFile.getCanonicalPath(),
                linkedRootCertFile.getCanonicalPath(), oldName};
        command.execute(args);
        checkLinkCert(oldRootCertFile.getCanonicalPath(), newRootCertFile.getCanonicalPath(), linkedRootCertFile.getCanonicalPath());
    }

    @Test
    public void testB13CertКeq() {
        //PKCS11HSMKeyTool certreq ${p11m} TOKEN_LABEL:${label_2} rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "certreq", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, aliases[0]};
        command.execute(args);
    }

    @Test
    public void testB14InstallCertificate() throws Exception {
        String alias = aliases[0];
        KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(TOKEN_PIN.toCharArray());
        ;
        final KeyStoreTools store = KeyStoreToolsFactory.getInstance(PKCS11_LIBRARY, SLOT_LABEL,
                Pkcs11SlotLabelType.SLOT_LABEL, null, protectionParameter, "batch-" + new Date().getTime());

        final KeyStore.PrivateKeyEntry caEntry = (KeyStore.PrivateKeyEntry) store.getKeyStore()
                .getEntry(aliases[6], protectionParameter);
        final X509Certificate[] theCertificate;
        try (final InputStream is = new FileInputStream(alias + ".pem")) {
            theCertificate = signCertificate(is, caEntry, store.getKeyStore().getProvider(), "SHA256WithRSA");
        }
        String certFileName = alias + "cert.pem";
        certFile = folder.newFile(certFileName);
        storeCertificates(theCertificate, certFile.getCanonicalPath());

        //PKCS11HSMKeyTool installcert ${p11m} TOKEN_LABEL:${label_2} rsa3cert.pem
        //<class name="org.ejbca.ui.cli.clientToolBoxTest.tests.InstallCert" />
        String[] args = new String[]{"PKCS11HSMKeyTool", "installcert", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, certFile.getCanonicalPath()};
        command.execute(args);

        checkInstalledCert(certFile.getCanonicalPath(), alias, protectionParameter, (X509Certificate[]) caEntry.getCertificateChain());
    }

    @Test
    public void testB15Token2AgainSinceNewCertInstalled() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_2} 10:35 rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, numberOfThreads + ":" + numberOfTests, aliases[0]};
        command.execute(args);
    }

    @Test
    public void testB16EncryptAndDecriptFileOnToken1() throws IOException {
        inFile = folder.newFile("orig.bin");
        File encriptedFile = folder.newFile("encr.bin");
        File decriptedFile = folder.newFile("decr.bin");
        try (FileOutputStream fileOutputStream = new FileOutputStream(inFile)) {
            fileOutputStream.write(CONTENT.getBytes());
        }
        //PKCS11HSMKeyTool encrypt ./p11m.so TOKEN_LABEL:${label_1} orig.bin encr1.bin rsa1
        String[] args = new String[]{"PKCS11HSMKeyTool", "encrypt", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, inFile.getCanonicalPath(), encriptedFile.getCanonicalPath(), aliases[0]};
        command.execute(args);
        //PKCS11HSMKeyTool decrypt ./p11m.so TOKEN_LABEL:${label_1} encr1.bin decr1.bin rsa1
        args = new String[]{"PKCS11HSMKeyTool", "decrypt", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, encriptedFile.getCanonicalPath(), decriptedFile.getCanonicalPath(), aliases[0]};
        command.execute(args);
        //<class name="org.ejbca.ui.cli.clientToolBoxTest.tests.FileDiffOfOriginAndResult" />
        checkDecryptedData(inFile.getCanonicalPath(), decriptedFile.getCanonicalPath());
    }

    @Test
    public void testB17SignFileOnToken1() throws IOException {
        File signedFile = folder.newFile("signed.bin");
        File verifiedFile = folder.newFile("verified.bin");

        //PKCS11HSMKeyTool sign ./p11m.so TOKEN_LABEL:${label_1} orig.bin signed1.bin ecc
        String[] args = new String[]{"PKCS11HSMKeyTool", "sign", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, inFile.getCanonicalPath(), signedFile.getCanonicalPath(), aliases[3]};
        command.execute(args);
        //PKCS11HSMKeyTool verify ./p11m.so TOKEN_LABEL:${label_1} signed1.bin verified1.bin ecc
        args = new String[]{"PKCS11HSMKeyTool", "verify", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, signedFile.getCanonicalPath(), verifiedFile.getCanonicalPath(), aliases[3]};
        command.execute(args);
        //<class name="org.ejbca.ui.cli.clientToolBoxTest.tests.FileDiffOfOriginAndResult" />
        checkDecryptedData(inFile.getCanonicalPath(), verifiedFile.getCanonicalPath());
    }


    @Test
    public void testB18EncryptFileWithCertificateForToken2() throws IOException {

        File encriptedFile = folder.newFile("encr2.bin");
        File decriptedFile = folder.newFile("decr2.bin");
        //PKCS11HSMKeyTool encrypt orig.bin encr2.bin rsa3cert.pem
        String[] args = new String[]{"PKCS11HSMKeyTool", "encrypt",
                inFile.getCanonicalPath(), encriptedFile.getCanonicalPath(), certFile.getCanonicalPath()};
        command.execute(args);

        //PKCS11HSMKeyTool decrypt ./p11m.so TOKEN_LABEL:${label_2} encr2.bin decr2.bin rsa3
        args = new String[]{"PKCS11HSMKeyTool", "decrypt", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, encriptedFile.getCanonicalPath(), decriptedFile.getCanonicalPath(), aliases[0]};
        command.execute(args);

        //<class name="org.ejbca.ui.cli.clientToolBoxTest.tests.FileDiffOfOriginAndResult" />
        checkDecryptedData(inFile.getCanonicalPath(), decriptedFile.getCanonicalPath());
    }

    @Test
    public void testB19SignFileOnToken2() throws IOException {
        File signedFile = folder.newFile("signed2.bin");
        File verifiedFile = folder.newFile("verified2.bin");

        //PKCS11HSMKeyTool sign ./p11m.so TOKEN_LABEL:${label_2} orig.bin signed2.bin rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "sign", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, inFile.getCanonicalPath(), signedFile.getCanonicalPath(), aliases[0]};
        command.execute(args);
        //PKCS11HSMKeyTool verify signed2.bin verified2.bin rsa3cert.pem
        args = new String[]{"PKCS11HSMKeyTool", "verify", signedFile.getCanonicalPath(), verifiedFile.getCanonicalPath(),
                certFile.getCanonicalPath()};
        command.execute(args);
        //<class name="org.ejbca.ui.cli.clientToolBoxTest.tests.FileDiffOfOriginAndResult" />
        checkDecryptedData(inFile.getCanonicalPath(), verifiedFile.getCanonicalPath());
    }


    @Test
    public void testC20DeleteKeyWithAliasDsaOnToken1() {
        //PKCS11HSMKeyTool delete ./p11m.so TOKEN_LABEL:${label_1} dsa
        String[] args = new String[]{"PKCS11HSMKeyTool", "delete", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, aliases[4], "-password", TOKEN_PIN};
        command.execute(args);
    }

    //    expected errors
    @Test
    public void testC21CfgKeyRsa3OnToken1ShouldFail() {
        //TODO check stderr "Key alias rsa2 does not exist"
//        exit.expectSystemExitWithStatus(2);  does not throw exception
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} ${id_1} 10:35 rsa3
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT_ID, numberOfThreads + ":" + numberOfTests, aliases[2]};
        command.execute(args);
    }

    @Test
    public void testC22KeyDsaDeletedFromToken1() {
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:${label_1} 10:35 dsa
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:" + SLOT_LABEL, numberOfThreads + ":" + numberOfTests, aliases[4]};
        command.execute(args);
        final String consoleOutput = errStream.toString();
        String message = "Key alias " + aliases[4] + " does not exist";
        assertTrue("System.err should contain: " + message, consoleOutput.contains(message));
    }

    @Test
    public void testC23TokenWithNonExistingLabel() {
        exit.expectSystemExitWithStatus(-1);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        //PKCS11HSMKeyTool test ${p11m} TOKEN_LABEL:nonexist 10:35 rsa1
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                "TOKEN_LABEL:nonexist", numberOfThreads + ":" + numberOfTests, aliases[0]};
        command.execute(args);
    }

    @Test
    public void testC24Token2WithLabelBadP11ModuleFileName() {
        exit.expectSystemExitWithStatus(-1);
        //PKCS11HSMKeyTool test /opt/PTK/lib/notExisting.so TOKEN_LABEL:${label_2}
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", "/opt/PTK/lib/notExisting.so",
                "TOKEN_LABEL:" + SLOT2_LABEL};
        command.execute(args);
    }

    @Test
    public void testC25TestKeyOnTokenByIndex() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT_INDEX, numberOfThreads + ":" + numberOfTests, aliases[0]};
        command.execute(args);
    }

    @Test
    public void testC26TestKeyOnToken2ByIndex() {
        exit.expectSystemExitWithStatus(0);
        int numberOfThreads = 10;
        int numberOfTests = 35;
        String[] args = new String[]{"PKCS11HSMKeyTool", "test", PKCS11_LIBRARY,
                SLOT2_INDEX, numberOfThreads + ":" + numberOfTests, aliases[2]};
        command.execute(args);
    }

    private X509Certificate[] generateKeyEntry(KeyStoreTools storeTools, String name,
                                               KeyStore.ProtectionParameter protectionParameter) throws Exception {
        String keyAlgorithm = "RSA";
        int keySize = 2048;
        String signAlgorithm = "Sha512WithRSA";
        KeyStore.Entry entry = storeTools.getKeyStore().getEntry(name, protectionParameter);
        if (entry != null) {
            storeTools.getKeyStore().deleteEntry(name);
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm, storeTools.getKeyStore().getProvider());
        kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        KeyPair keyPair = kpg.generateKeyPair();
        X509Certificate cert = signCertificate(new X500Principal("CN=" + name), keyPair.getPublic(), null,
                keyPair.getPrivate(), storeTools.getKeyStore().getProvider(), signAlgorithm);
        X509Certificate[] chain = new X509Certificate[]{cert};
        entry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(), chain);
        storeTools.getKeyStore().setEntry(name, entry, protectionParameter);
        return chain;
    }

    private X509Certificate signCertificate(X500Principal subjectDN, PublicKey subjectPublicKey, X509Certificate caCert, PrivateKey issuerPrivateKey,
                                            Provider p11Provider, String algorithm) throws Exception {
        BigInteger serial = new BigInteger(128, SecureRandom.getInstance("PKCS11", p11Provider));
        Date from = new Date((new Date()).getTime() - 600000L);
        Date to = new Date(from.getTime() + 1827387392L);
        X500Principal issuerDN = caCert != null ? caCert.getSubjectX500Principal() : subjectDN;
        PublicKey issuerPublicKey = caCert != null ? caCert.getPublicKey() : subjectPublicKey;
        X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(issuerDN, serial, from, to, subjectDN, subjectPublicKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        v3Bldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey));
        v3Bldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerPublicKey));
        v3Bldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        X509CertificateHolder certHldr = v3Bldr.build((new JcaContentSignerBuilder(algorithm)).setProvider(p11Provider).build(issuerPrivateKey));
        X509Certificate cert = (new JcaX509CertificateConverter()).setProvider(new BouncyCastleProvider()).getCertificate(certHldr);
        cert.checkValidity(new Date());
        cert.verify(issuerPublicKey);
        return cert;
    }

    private static void writeChainToStream(final OutputStream os, final X509Certificate[] chain) throws Exception {
        for (final X509Certificate cert : chain) {
            os.write(cert.getEncoded());
        }
    }

    private void checkLinkCert(
            final String oldRootCertFileName,
            final String newRootCertFileName,
            final String linkCertFileName) throws Exception {
        final X509Certificate oldCert;
        try (final InputStream is = new FileInputStream(oldRootCertFileName)) {
            oldCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(is);
        }
        final X509Certificate newCert;
        try (final InputStream is = new FileInputStream(newRootCertFileName)) {
            newCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(is);
        }
        final X509Certificate linkCert;
        try (final InputStream is = new FileInputStream(linkCertFileName)) {
            linkCert = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(is);
        }
        assertTrue("Verification failed", CertTools.verify(linkCert, Collections.singleton(oldCert)));
        assertEquals(linkCert.getSubjectX500Principal(), newCert.getSubjectX500Principal());
        assertEquals(linkCert.getSubjectAlternativeNames(), newCert.getSubjectAlternativeNames());
        assertEquals(linkCert.getBasicConstraints(), newCert.getBasicConstraints());
        assertEquals(linkCert.getCriticalExtensionOIDs(), newCert.getCriticalExtensionOIDs());
        final Set<String> nonCriticalLinkCertOIDs = linkCert.getNonCriticalExtensionOIDs();
        assertTrue("Name is changed from old to new so the linkcert must contain the 'nameChange' OID (2.23.136.1.1.6.1).", nonCriticalLinkCertOIDs.remove("2.23.136.1.1.6.1"));
        assertEquals(nonCriticalLinkCertOIDs, newCert.getNonCriticalExtensionOIDs());
        for (final String oid : newCert.getNonCriticalExtensionOIDs()) {
            if (oid.equals("2.5.29.35")) {
                continue;// AuthorityKeyIdentifier must be different.
            }
            assertArrayEquals("OID " + oid + " differs.", linkCert.getExtensionValue(oid), newCert.getExtensionValue(oid));
        }
        for (final String oid : newCert.getCriticalExtensionOIDs()) {
            assertArrayEquals("OID " + oid + " differs.", linkCert.getExtensionValue(oid), newCert.getExtensionValue(oid));
        }
    }

    public X509Certificate[] signCertificate(InputStream certReqStream, KeyStore.PrivateKeyEntry ca, Provider p11Provider, String algorithm) throws Exception {
        X509Certificate caCert = (X509Certificate) ca.getCertificate();
        PrivateKey issuerPrivateKey = ca.getPrivateKey();
        PemReader reader = new PemReader(new InputStreamReader(certReqStream));

        PemObject pemObject;
        try {
            pemObject = reader.readPemObject();
        } finally {
            reader.close();
        }

        JcaPKCS10CertificationRequest a = new JcaPKCS10CertificationRequest(pemObject.getContent());
        X509Certificate endUserCert = signCertificate(new X500Principal(a.getSubject().getEncoded()), a.getPublicKey(), caCert, issuerPrivateKey, p11Provider, algorithm);
        List<X509Certificate> caChain = new ArrayList(Arrays.asList((X509Certificate[]) ca.getCertificateChain()));
        caChain.add(0, endUserCert);
        return caChain.toArray(new X509Certificate[0]);
    }

    private void storeCertificates(Certificate[] certs, String name) throws Exception {
        try (OutputStream os = new FileOutputStream(name)) {
            try (PemWriter pw = new PemWriter(new OutputStreamWriter(os))) {
                for (Certificate cert : certs) {
                    pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
                }
            }
        }
    }


    public static void checkInstalledCert(final String certFile, final String keyAlias,
                                          final KeyStore.ProtectionParameter protectionParameter,
                                          X509Certificate[] caCertChain) throws Exception {
        final KeyStoreTools store = KeyStoreToolsFactory.getInstance(PKCS11_LIBRARY, SLOT_LABEL,
                Pkcs11SlotLabelType.SLOT_LABEL, null, protectionParameter, "batch-" + new Date().getTime());

        final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) store.getKeyStore()
                .getEntry(keyAlias, protectionParameter);
        final X509Certificate[] pemChain;
        try (final InputStream is = new FileInputStream(certFile)) {
            pemChain = CertTools.getCertsFromPEM(is, X509Certificate.class).toArray(new X509Certificate[0]);
        }
        final X509Certificate[] p11chain = (X509Certificate[]) entry.getCertificateChain();

        assertEquals("Certificate chain length on slot: ", 2, p11chain.length);
        assertTrue("Verification failed", CertTools.verify(p11chain[0], Arrays.asList(caCertChain)));
        assertTrue("Certificate chains in pem file and on slot should be equal ", CertTools.compareCertificateChains(p11chain, pemChain));
    }

    public static void checkDecryptedData(final String originalFile, final String resultFile) throws IOException {
        final String original = new String(Files.readAllBytes(Paths.get(originalFile)));
        final String decripted = new String(Files.readAllBytes(Paths.get(resultFile)));
        assertEquals(original, decripted);
    }

}
