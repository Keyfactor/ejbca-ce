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

import java.io.File;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * <p>System tests for {@link RecoverCommand}.
 *
 * <p>Run these tests with:
 * <pre>
 *     ant test:runone -Dtest.runone=RecoverCommandTest
 * </pre>.
 */
public class RecoverCommandTest {
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(RecoverCommandTest.class.getSimpleName());
    private X509CA ca;

    @BeforeClass
    public static void installBcProvider() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void createCa() throws Exception {
        // CA ID = -578467253
        ca = CaTestUtils.createTestX509CA("CN=Recovery Test", null, false);
        if (!EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).existsCa(-578467253)) {
            EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).addCA(authenticationToken, ca);
        }
    }

    @After
    public void removeCa() throws Exception {
        if (ca != null) {
            CaTestUtils.removeCa(authenticationToken, ca.getCAInfo());
        }
    }

    @Test
    public void testRecover1EndEntityAnd1Certificate() throws Exception {
        final File serverLog = File.createTempFile("server.log", null);
        try {
            FileUtils.writeLines(serverLog, Arrays.asList(
                    // Log line produced when a new end entity is added
                    "2020-09-22 14:49:22,685 INFO  [org.cesecore.audit.impl.log4j.Log4jDevice] (default task-2) " +
                            "2020-09-22 14:49:22+02:00;RA_ADDENDENTITY;SUCCESS;RA;CORE;CN=SuperAdmin,O=PrimeKey Solutions AB,C=SE;" +
                            "-2107852779;;SUP-2684;msg=Added end entity SUP-2684.;caid=-578467253;cardnumber=;" +
                            "certificateprofileid=1;endentityprofileid=1;extendedInformation= [version:4.0], " +
                            "[type:0], [subjectdirattributes:], [maxfailedloginattempts:-1], [remainingloginattempts:-1], " +
                            "[KEYSTORE_ALGORITHM_TYPE:RSA], [KEYSTORE_ALGORITHM_SUBTYPE:2048]};status=10;subjectAltName=B64:RE5TTkFNRT13d3cuZXhhbXBsZS5jb20=;" +
                            "subjectDN=B64:Q049U1VQLTI2ODQsTz1QcmltZUtleSBTb2x1dGlvbnMgQUIsQz1TRQ==;subjectEmail=;" +
                            "timecreated=Tue Sep 22 14:49:22 CEST 2020;timemodified=Tue Sep 22 14:49:22 CEST 2020;" +
                            "tokentype=2;type=129;username=SUP-2684",
                    // Log line produced when a new certificate is issued
                    "2020-09-22 14:49:22,928 INFO  [org.cesecore.audit.impl.log4j.Log4jDevice] (default task-2) " +
                            "2020-09-22 14:49:22+02:00;CERT_CREATION;SUCCESS;CERTIFICATE;CORE;CN=SuperAdmin,O=PrimeKey Solutions AB,C=SE;" +
                            "-578467253;4B2387786EFC0F2F673336A61EC8E5AC;SUP-2684;subjectdn=CN=SUP-2684,O=PrimeKey Solutions AB,C=SE;" +
                            "certprofile=1;issuancerevocationreason=-1;cert=MIIC6TCCAo+gAwIBAgIQSyOHeG78Dy9nMzamHsjlrDAKBggqhkjO" +
                            "PQQDAjBVMR8wHQYDVQQDDBZTdG9ybWh1YiBFQyBTdGFnaW5nIEcxMSUwIwYDVQQKDBxTdG9ybWh1YiBUcnVzdCBTZXJ2aWNlcyBMdGQuMQs" +
                            "wCQYDVQQGEwJTRTAeFw0yMDA5MjIxMjM5MjJaFw0yMDA5MjMxMjM5MjJaMEAxETAPBgNVBAMMCFNVUC0yNjg0MR4wHAYDVQQKDBVQcmltZU" +
                            "tleSBTb2x1dGlvbnMgQUIxCzAJBgNVBAYTAlNFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Q/OrUD74WBieYH19NXqf4O44" +
                            "IkpdEYEG/GkruuWkzktWeQXJYNdqd9fT9zalg9XTNvvWvHQPdfjQy+84v4JjqpbN65iBpDlrBqxXaM+whskujxU+9c1ZXIqTx1Higq+qCK0" +
                            "UxxoSVRNv6a8PhSSv8mO9EIxz7EJ9zPTSDEh6UHQ5f81QKnD8OOpij/ij8dzrQHRrxdy3O+jNCJ0LPOSx+OjJChssd6VdaTPdSXnhWKcGwk" +
                            "tgxT4WGCoZBwmKj6H3KKHwtMuVJJMEEvajaoKeRI2fTzvvsbZZimTsodT92Pz/WwnZXBjZI85jHnjmB1Cvhr7yvX/tqKTiH1m47TrdwIDAQ" +
                            "ABo4GKMIGHMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUm2yElYIOUB6S9YaNGusNsAKzOVwwJwYDVR0lBCAwHgYIKwYBBQUHAwIGCCsGA" +
                            "QUFBwMEBggrBgEFBQcDATAdBgNVHQ4EFgQUBUL7DVKkYM0Glt50YAg4IMcbb3MwDgYDVR0PAQH/BAQDAgWgMAoGCCqGSM49BAMCA0gAMEUC" +
                            "IFJQcTKBKt/pdxOaFolBRTM6k//WtGDhQIJXWu/2Lb+2AiEAkoCiIHSKmHsyjNLWU8j3vErWYCyV83SC3Ssgcos4hw8="));
            final RecoverCommand command = new RecoverCommand();
            final String[] args = new String[] { "--log-file", serverLog.getAbsolutePath(), "--execute" };
            assertEquals(CommandResult.SUCCESS.getReturnCode(), command.execute(args).getReturnCode());
            
            final String username = "SUP-2684";
            EndEntityInformation ei = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(authenticationToken, username);
            assertNotNull("User was not recovered.", ei);
            assertEquals("End entity DN was not recovered correctly", "CN=SUP-2684,O=PrimeKey Solutions AB,C=SE", ei.getDN());
            assertEquals("End entity Altname was not recovered correctly", "DNSNAME=www.example.com", ei.getSubjectAltName());
            assertEquals("End entity EE profile ID was not recovered correctly", 1, ei.getEndEntityProfileId());
            assertEquals("End entity Cert profile ID was not recovered correctly", 1, ei.getCertificateProfileId());
            assertEquals("End entity CA ID was not recovered correctly", -578467253, ei.getCAId());
            assertEquals("End entity token type was not recovered correctly", 2, ei.getTokenType());

            CertificateInfo certInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getCertificateInfo("8267fbda40c8f1013fcef109f09ecf457193daef");
            assertNotNull("Certificate was not recovered.", certInfo);
            assertEquals("Cert username was not recovered correctly", "SUP-2684", certInfo.getUsername());
            assertEquals("Cert DN was not recovered correctly", "CN=SUP-2684,O=PrimeKey Solutions AB,C=SE", certInfo.getSubjectDN());
            assertEquals("Cert Cert profile ID was not recovered correctly", 1, certInfo.getCertificateProfileId());
            final CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(authenticationToken, ei.getCAId());
            final List<Certificate> certificateChain = caInfo.getCertificateChain();
            final String caFingerprint = CertTools.getFingerprintAsString(certificateChain.get(0));
            assertEquals("Cert CA fingerprint was not recovered correctly", caFingerprint, certInfo.getCAFingerprint());
        } finally {
            FileUtils.deleteQuietly(serverLog);
            EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST)
                    .removeCertificate("8267fbda40c8f1013fcef109f09ecf457193daef");
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class)
                    .revokeAndDeleteUser(authenticationToken, "SUP-2684", RevocationReasons.UNSPECIFIED.getDatabaseValue());
        }
    }

    @Test
    public void testIrrelevantLogLines() throws Exception {
        final File serverLog = File.createTempFile("server.log", null);
        try {
            FileUtils.writeLines(serverLog, Arrays.asList(
                "2020-09-25 18:08:26,150 ERROR [org.ejbca.peerconnector.client.PeerConnectorPool] (EJB defau" +
                        "lt - 1) Failed connection to https://va.nautilus:8443/ejbca/peer/v1: Connect to va." +
                        "nautilus:8443 [va.nautilus/192.168.56.201] failed: Connection timed out (Connection" +
                        " timed out)",
                "2020-09-25 18:08:26,150 DEBUG [org.ejbca.peerconnector.ra.PeerRaSlaveServiceBean] (EJB defa" +
                        "ult - 1) Delay was -125167. Will not sleep.",
                "2020-09-25 18:08:28,244 INFO  [org.cesecore.audit.impl.log4j.Log4jDevice] (default task-1) " +
                        "2020-09-25 18:08:28+02:00;ACCESS_CONTROL;SUCCESS;ACCESSCONTROL;CORE;CN=SuperAdmin,O" +
                        "=PrimeKey Solutions AB,C=SE;;;;resource0=/administrator;resource1=/system_functiona" +
                        "lity/view_administrator_privileges"));
            final RecoverCommand command = new RecoverCommand();
            final String[] args = new String[] { "--log-file", serverLog.getAbsolutePath(), "--execute" };
            assertEquals(CommandResult.SUCCESS.getReturnCode(), command.execute(args).getReturnCode());
        } finally {
            FileUtils.deleteQuietly(serverLog);
        }
    }
}
