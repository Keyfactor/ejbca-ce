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

import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Arrays;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Basic system tests for the Asn1DumpCommand
 * 
 * @version $Id$
 *
 */
public class Asn1DumpCommandTest {

    private static File pemFile;

    private Asn1DumpCommand asn1DumpCommand = new Asn1DumpCommand();

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        pemFile = File.createTempFile("test", null);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        byte[] pem = CertTools.getPemFromCertificateChain(Arrays.asList(certificate));
        FileOutputStream fileOutputStream = new FileOutputStream(pemFile);
        try {
            fileOutputStream.write(pem);
        } finally {
            fileOutputStream.close();
        }
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (pemFile.exists()) {
            FileTools.delete(pemFile);
        }
    }

    @Test
    public void testCommand() {
        String[] args = new String[] { "asn1dump", pemFile.getAbsolutePath() };
        try {
            asn1DumpCommand.execute(args);
        } catch (Exception e) {
            // This command produces only console output, but this will at least verify that command hasn't
            // broken for some external reason.
            fail("Command did not execute properly.");
        }
    }
}
