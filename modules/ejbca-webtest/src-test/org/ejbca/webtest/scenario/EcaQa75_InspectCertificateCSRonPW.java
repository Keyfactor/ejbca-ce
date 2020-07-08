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

package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.InspectCertificateCsrHelper;
import org.ejbca.webtest.helper.PublicWebHelper;
import org.ejbca.webtest.util.TestFileResource;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Inspect each certificate/CSR type's content and compare with OpenSSL
 *
 * @version $Id: EcaQa75_InspectCertificateCSRonPW 35131 2020-05-25 15:41:55Z margaret_d_thomas $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa75_InspectCertificateCSRonPW extends WebTestBase {
    private static WebDriver webDriver;

    //Helper
    private static PublicWebHelper publicWebHelper;
    private static InspectCertificateCsrHelper inspectCertificateCsrHelper;

    //TestData
    private static class TestData {
        static final String INVALID_FILE_TYPE = new TestFileResource("INVALID_FILE_TO_UPLOAD.txt").getFileAbsolutePath();
        static final String PEM_CERTIFICATE = new TestFileResource("ManagementCA_ECAQA75.pem").getFileAbsolutePath();
        static final String DER_CERTIFICATE = new TestFileResource("ManagementCA_ECAQA75.der").getFileAbsolutePath();
        static final String CVCERT_CERTIFICATE = new TestFileResource("SEMYCVCA00000_SEMYCVCA00000.cvcert").getFileAbsolutePath();
        static final String P12_CERTIFICATE = new TestFileResource("2.0.0.backup.p12").getFileAbsolutePath();

        //Expected Certificate Values
        static final String CERTIFICATE_FILETYPE = "File is of type: X.509";
        static final String CERITIFICATE_P12_FILETYPE = "File is of type: ASN.1";
        static final String CERTIFICATE_CVCERT_FILETYPE = "File is of type: CVC";

        //PEM File
        static final String PEM_FILE_CONTENT = "[0]         Version: 3\n" +
                "         SerialNumber: 2363212885488714878\n" +
                "             IssuerDN: CN=ManagementCA650b1,OU=QA,O=PrimeKey Labs GmbH,C=DE\n" +
                "           Start Date: Wed Feb 03 14:16:38 CET 2016\n" +
                "           Final Date: Sat Jan 31 14:16:38 CET 2026\n" +
                "            SubjectDN: CN=ManagementCA650b1,OU=QA,O=PrimeKey Labs GmbH,C=DE\n" +
                "           Public Key: RSA Public Key [8c:e5:e8:91:5d:06:96:ac:28:ef:9d:d8:da:dd:99:6e:a2:8a:38:4f]\n" +
                "            modulus: c4f473fa66018cdf1792d665370b019de3ffd113d9ff9efee8f1c6108d664adb5bded79b54e8d85ce8544461c9bc78491947e8cbf5564b27fe5a0820038a1fc76bef993b36186d45d4748d438bd873c71161ceb063807deb5e14e9f111a6cf42a97807386e0372ae38a6e3a66b6b610c7cef3c5d2b8df5f41eacd75661fbb709acbd9f6a69a89c7ad112a1d7d151073f6e94f00ef9eb3e1181e2abb9fc229804e43b9a0e8e3d61dbabe4bccb16f572ee2e45bad0db58c1b768670337673b4c51de8f014a2decae88659a0320b879f41328bf5e2ca4bd64e0a446938fbb46c83ea93f096e5d802f590d14f1205811d9feeaaad75d1dbcde1687e6551de0790463\n" +
                "    public exponent: 10001\n" +
                "\n" +
                "  Signature Algorithm: SHA256WITHRSA\n" +
                "            Signature: 4479cf9da8c53bc6ebf1a33e494a77de028c74b2\n" +
                "                       5cc48c5f9c54b8cd7aa46b89f7c2446c84fd7705\n" +
                "                       ee5b28401d236f6f07ef9442c01af00dca6167c4\n" +
                "                       4ce3c95ec33184d220d6c664679f433cf8c39484\n" +
                "                       7ce6cd5b537d784bc58e2877d19047c2ec177b0b\n" +
                "                       67b1fb9c43033bf845b2446e973e8d141762846d\n" +
                "                       a6bb5585ce188a93d473522a8c71cf0b743265c0\n" +
                "                       cbc5ae35f32d9ecbf0580c97e541ba444c5e5034\n" +
                "                       2ccc7cc0dfd430537fd7089e86e6b03de200c7be\n" +
                "                       303800c4e487289fa5b0a8dfc53d09d168e5e298\n" +
                "                       42e4a7af6a0279489f158cb8af5f1cc43eb42e43\n" +
                "                       3d3ee4acc9c93e49ac3b28028e6d6e7309787b18\n" +
                "                       1257040a81f19b9cd084fd5924e67b01\n" +
                "       Extensions: \n" +
                "                       critical(false) 2.5.29.14 value = DER Octet String[20] \n" +
                "\n" +
                "                       critical(true) BasicConstraints: isCa(true)\n" +
                "                       critical(false) 2.5.29.35 value = Sequence\n" +
                "    Tagged [0] IMPLICIT \n" +
                "        DER Octet String[20] \n" +
                "\n" +
                "                       critical(true) KeyUsage: 0x86";


        //DER File
        static final String DER_FILE_CONTENT = "[0]         Version: 3\n" +
                "         SerialNumber: 2363212885488714878\n" +
                "             IssuerDN: CN=ManagementCA650b1,OU=QA,O=PrimeKey Labs GmbH,C=DE\n" +
                "           Start Date: Wed Feb 03 14:16:38 CET 2016\n" +
                "           Final Date: Sat Jan 31 14:16:38 CET 2026\n" +
                "            SubjectDN: CN=ManagementCA650b1,OU=QA,O=PrimeKey Labs GmbH,C=DE\n" +
                "           Public Key: RSA Public Key [8c:e5:e8:91:5d:06:96:ac:28:ef:9d:d8:da:dd:99:6e:a2:8a:38:4f]\n" +
                "            modulus: c4f473fa66018cdf1792d665370b019de3ffd113d9ff9efee8f1c6108d664adb5bded79b54e8d85ce8544461c9bc78491947e8cbf5564b27fe5a0820038a1fc76bef993b36186d45d4748d438bd873c71161ceb063807deb5e14e9f111a6cf42a97807386e0372ae38a6e3a66b6b610c7cef3c5d2b8df5f41eacd75661fbb709acbd9f6a69a89c7ad112a1d7d151073f6e94f00ef9eb3e1181e2abb9fc229804e43b9a0e8e3d61dbabe4bccb16f572ee2e45bad0db58c1b768670337673b4c51de8f014a2decae88659a0320b879f41328bf5e2ca4bd64e0a446938fbb46c83ea93f096e5d802f590d14f1205811d9feeaaad75d1dbcde1687e6551de0790463\n" +
                "    public exponent: 10001\n" +
                "\n" +
                "  Signature Algorithm: SHA256WITHRSA\n" +
                "            Signature: 4479cf9da8c53bc6ebf1a33e494a77de028c74b2\n" +
                "                       5cc48c5f9c54b8cd7aa46b89f7c2446c84fd7705\n" +
                "                       ee5b28401d236f6f07ef9442c01af00dca6167c4\n" +
                "                       4ce3c95ec33184d220d6c664679f433cf8c39484\n" +
                "                       7ce6cd5b537d784bc58e2877d19047c2ec177b0b\n" +
                "                       67b1fb9c43033bf845b2446e973e8d141762846d\n" +
                "                       a6bb5585ce188a93d473522a8c71cf0b743265c0\n" +
                "                       cbc5ae35f32d9ecbf0580c97e541ba444c5e5034\n" +
                "                       2ccc7cc0dfd430537fd7089e86e6b03de200c7be\n" +
                "                       303800c4e487289fa5b0a8dfc53d09d168e5e298\n" +
                "                       42e4a7af6a0279489f158cb8af5f1cc43eb42e43\n" +
                "                       3d3ee4acc9c93e49ac3b28028e6d6e7309787b18\n" +
                "                       1257040a81f19b9cd084fd5924e67b01\n" +
                "       Extensions: \n" +
                "                       critical(false) 2.5.29.14 value = DER Octet String[20] \n" +
                "\n" +
                "                       critical(true) BasicConstraints: isCa(true)\n" +
                "                       critical(false) 2.5.29.35 value = Sequence\n" +
                "    Tagged [0] IMPLICIT \n" +
                "        DER Octet String[20] \n" +
                "\n" +
                "                       critical(true) KeyUsage: 0x86";

        //P12 File
        static final String P12_FILE_CONTENT = "BER Sequence\n" +
                "    Integer(3)\n" +
                "    BER Sequence\n" +
                "        ObjectIdentifier(1.2.840.113549.1.7.1)\n" +
                "        BER Tagged [0]\n" +
                "            BER Constructed Octet String[3830] \n" +
                "    Sequence\n" +
                "        Sequence\n" +
                "            Sequence\n" +
                "                ObjectIdentifier(1.3.14.3.2.26)\n" +
                "                NULL\n" +
                "            DER Octet String[20] \n" +
                "        DER Octet String[16] \n" +
                "        Integer(2000)";

        //CVCERT File
        static final String CVCERT_FILE_CONTENT = "7f21 CV_CERTIFICATE  \n" +
                "   7f4e CERTIFICATE_BODY  \n" +
                "      5f29 PROFILE_IDENTIFIER  0\n" +
                "      42 CA_REFERENCE  SE/MYCVCA/00000\n" +
                "      7f49 PUBLIC_KEY  \n" +
                "         6 OID  0.4.0.127.0.7.2.2.2.1.2\n" +
                "         81 MODULUS  [2048]  B76E03699A0D4BC64268D0B780BA3D5A4A1A0BAC78FCC141AC4DACFB867B0D97264284FE4CCC7A082B10ECA932256182C401B9021094B4E8E34DDB3774C357EB9BA761CB7E1BE574670AEFF1BA4DE5B1AA96A67748B5F4978BFC54A3F57B9111CD070098B71541BF54B1505C1FF2BCAB6CB56BA3E9032660B706ECD564714E0EDDDBADC1542A1122695E879C839FF1BF63EFA670590A8EB4606C1352C52BB17DA00DD9C284BB797AF8B3C35B57192EB20923ADBDC20318F3F5EDD02F1502AAAC977DB420E1E669301578AFA6DBFDA31D2AA1DB577E998B2C0A84D9D3051B7DCFE38B5CF90A44FB43BB36033845B291048C3920D80BDA6163388B47689ED399AB\n" +
                "         82 EXPONENT  010001\n" +
                "      5f20 HOLDER_REFERENCE  SE/MYCVCA/00000\n" +
                "      7f4c HOLDER_AUTH_TEMPLATE  \n" +
                "         6 OID  0.4.0.127.0.7.3.1.2.1\n" +
                "         53 ROLE_AND_ACCESS_RIGHTS  C3: CVCA/DG3+DG4\n" +
                "      5f25 EFFECTIVE_DATE  2016-02-16\n" +
                "      5f24 EXPIRATION_DATE  2041-02-16\n" +
                "   5f37 SIGNATURE  44F2EEA6F855174599C94F43DC5BF5AE2E53DAA99ED85A828EF043154C2441EC3CE5C28F2330A10AEE69D0FED486C92AFE497410115DD85B5555CC65A3EF4DB0D702DBEE9520956B865A1359BC60FE2ADD6BEB962D3547E6E2C785DFD8E751BD048E31ACF53FD60F62ED6FA47769BEDF1B6FF49ADB699772624B03D98E8564A31B337018618C1FC5A605490712F100F807C470822311FAB32737286474C88A07D9D3CFF68DC13B24448784B822711E6FC13A089E34B7B3C9BF323268221E480479B442CEDB5B89D721E18C925E6B6BB158849A1DBD414759515FDB1F63C106D0230EB89E3DE687BCDA3198CBF2B744C2AB77FFDC32973933194F72367A56BAF7";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        cleanup(); // clean up data from aborted test runs
        webDriver = getWebDriver();
        // Init helpers
        publicWebHelper = new PublicWebHelper(webDriver);
        inspectCertificateCsrHelper = new InspectCertificateCsrHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        cleanup();
        // super
        afterClass();
    }

    /**
     * Removes generated artifacts
     */
    private static void cleanup() {

    }

    @Test
    public void stepA_assertFileNotFound() {
        publicWebHelper.openPage(getPublicWebUrl());
        inspectCertificateCsrHelper.clickInspectCertificateCSR();
        inspectCertificateCsrHelper.setCertificateFile(TestData.INVALID_FILE_TYPE);
        inspectCertificateCsrHelper.clickOK();
        inspectCertificateCsrHelper.assertCsrDumpHeader("File is of type: unknown");
    }

    @Test
    public void stepB_UploadPemCertificate() {
        publicWebHelper.openPage(getPublicWebUrl());
        inspectCertificateCsrHelper.clickInspectCertificateCSR();
        inspectCertificateCsrHelper.setCertificateFile(TestData.PEM_CERTIFICATE);
        inspectCertificateCsrHelper.clickOK();

        //Assert Pem Certificate File Type
        inspectCertificateCsrHelper.assertCsrDumpHeader(TestData.CERTIFICATE_FILETYPE);

        //Assert Pem Certificate Content
        inspectCertificateCsrHelper.assertCertificateContent(TestData.PEM_FILE_CONTENT);
    }

    @Test
    public void stepC_UploadDerCertificate() {
        publicWebHelper.openPage(getPublicWebUrl());
        inspectCertificateCsrHelper.clickInspectCertificateCSR();
        inspectCertificateCsrHelper.setCertificateFile(TestData.DER_CERTIFICATE);
        inspectCertificateCsrHelper.clickOK();

        //Assert Der Certificate File Type
        inspectCertificateCsrHelper.assertCsrDumpHeader(TestData.CERTIFICATE_FILETYPE);

        //Assert Der Certificate Content
        inspectCertificateCsrHelper.assertCertificateContent(TestData.DER_FILE_CONTENT);
    }

    @Test
    public void stepD_UploadP12Certificate() {
        publicWebHelper.openPage(getPublicWebUrl());
        inspectCertificateCsrHelper.clickInspectCertificateCSR();
        inspectCertificateCsrHelper.setCertificateFile(TestData.P12_CERTIFICATE);
        inspectCertificateCsrHelper.clickOK();

        //Assert P12 Certificate File Type
        inspectCertificateCsrHelper.assertCsrDumpHeader(TestData.CERITIFICATE_P12_FILETYPE);

        //Assert P12 Certificate Content
        inspectCertificateCsrHelper.assertCertificateContent(TestData.P12_FILE_CONTENT);
    }

    @Test
    public void stepE_UploadCVCertCertificate() {
        publicWebHelper.openPage(getPublicWebUrl());
        inspectCertificateCsrHelper.clickInspectCertificateCSR();
        inspectCertificateCsrHelper.setCertificateFile(TestData.CVCERT_CERTIFICATE);
        inspectCertificateCsrHelper.clickOK();

        //Assert CVCERT Certificate File Type
        inspectCertificateCsrHelper.assertCsrDumpHeader(TestData.CERTIFICATE_CVCERT_FILETYPE);

        //Assert CVCERT Certificate Content
        inspectCertificateCsrHelper.assertCertificateContent(TestData.CVCERT_FILE_CONTENT);
    }
}
