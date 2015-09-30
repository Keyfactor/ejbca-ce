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
package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CaImportCertCommandTest {

    private static final String CA_NAME = "CaImportCertCommandTest";
    private static final String CA_DN = "CN=" + CA_NAME;
    private static final String USERNAME = "CaImportCertCommandTest";
    private static final String CERTIFICATE_DN = "C=SE,O=foo,CN=" + USERNAME;

    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(CaImportCertCommandTest.class.getSimpleName());

    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private CaImportCertCommand command = new CaImportCertCommand();
    private X509CA ca;
    private File certificateFile;
    private BigInteger certificateSerialNumber;


    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        //Creates a CA with AlgorithmConstants.SIGALG_SHA256_WITH_RSA
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
        certificateFile = File.createTempFile("test", null);
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        EndEntityInformation endEntityInformation = new EndEntityInformation(USERNAME, CERTIFICATE_DN, ca.getCAId(), null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                SecConst.TOKEN_SOFT_PEM, 0, null);
        endEntityInformation.setPassword("foo123");
        endEntityManagementSession.addUser(authenticationToken, endEntityInformation, false);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), endEntityInformation.getUsername(), endEntityInformation.getPassword());
        Certificate certificate = ((X509ResponseMessage) certificateCreateSession.createCertificate(authenticationToken, endEntityInformation, req,
                X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate();
        certificateSerialNumber = CertTools.getSerialNumber(certificate);
        FileOutputStream fileOutputStream = new FileOutputStream(certificateFile);
        try {
            fileOutputStream.write(CertTools.getPemFromCertificateChain(Arrays.asList(certificate)));
        } finally {
            fileOutputStream.close();
        }
        List<Certificate> certs = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(USERNAME));
        if (certs.size() > 0) {
            for (Certificate cert : certs) {
                internalCertificateStoreSession.removeCertificate(cert);
            }
        }
        endEntityManagementSession.deleteUser(authenticationToken, USERNAME);

    }

    @After
    public void tearDown() throws Exception {
        if (ca != null) {
            caSession.removeCA(authenticationToken, ca.getCAId());
        }
        if (certificateFile.exists()) {
            FileTools.delete(certificateFile);
        }
        if (endEntityAccessSession.findUser(authenticationToken, USERNAME) != null) {
            endEntityManagementSession.deleteUser(authenticationToken, USERNAME);
        }
        
        if (endEntityAccessSession.findUser(authenticationToken, USERNAME) != null) {
            endEntityManagementSession.deleteUser(authenticationToken, USERNAME);
        }
        List<Certificate> userCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(USERNAME));
        if (userCerts.size() > 0) {
            for (Certificate certificate : userCerts) {
                internalCertificateStoreSession.removeCertificate(certificate);
            }
        }
        if (endEntityAccessSession.findUser(authenticationToken, CERTIFICATE_DN) != null) {
            endEntityManagementSession.deleteUser(authenticationToken, CERTIFICATE_DN);
        }
        List<Certificate> dnCerts = EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(CERTIFICATE_DN));
        if (dnCerts.size() > 0) {
            for (Certificate certificate : dnCerts) {
                internalCertificateStoreSession.removeCertificate(certificate);
            }
        }
    }

    @Test
    public void testCommand1() throws CADoesntExistsException, AuthorizationDeniedException {
        String[] args = new String[] { USERNAME, "foo123", CA_NAME, "ACTIVE", "--email", "foo@foo.com", certificateFile.getAbsolutePath(),
                "--eeprofile", "EMPTY", "--certprofile", "ENDUSER" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        assertNotNull("Certificate was not imported.", endEntityAccessSession.findUser(authenticationToken, USERNAME));
    }
    
    @Test
    public void testCommand2() throws CADoesntExistsException, AuthorizationDeniedException {
        String[] args = new String[] { USERNAME, "foo123", CA_NAME, "ACTIVE", certificateFile.getAbsolutePath(),
                "--eeprofile", "EMPTY", "--certprofile", "ENDUSER" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        assertNotNull("Certificate was not imported.", endEntityAccessSession.findUser(authenticationToken, USERNAME));
    }

    
    @Test
    public void testImportRevoked() throws AuthorizationDeniedException {
        String[] args = new String[] { USERNAME, "foo123", CA_NAME, "REVOKED", certificateFile.getAbsolutePath(),
                "--eeprofile", "EMPTY", "--certprofile", "ENDUSER" };
                assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, USERNAME);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_REVOKED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.UNSPECIFIED.getDatabaseValue(), certificateStatus.revocationReason);
    }
    
    @Test
    public void testImportRevokedWithReasonAndTime() throws AuthorizationDeniedException, ParseException {
        String[] args = new String[] { USERNAME, "foo123", CA_NAME, "REVOKED", certificateFile.getAbsolutePath(),
                "--eeprofile", "EMPTY", "--certprofile", "ENDUSER", "--revocation-reason", RevocationReasons.CACOMPROMISE.getStringValue(), "--revocation-time", "2015.05.04-10:15" };
        assertEquals(CommandResult.SUCCESS, command.execute(args));
        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(authenticationToken, USERNAME);
        assertNotNull("Certificate was not imported.", endEntityInformation);
        assertEquals("Certificate was imported with incorrect status", EndEntityConstants.STATUS_REVOKED, endEntityInformation.getStatus());
        CertificateStatus certificateStatus = certificateStoreSession.getStatus(CA_DN, certificateSerialNumber);
        assertEquals("Certificate revocation reason was incorrectly imported.", RevocationReasons.CACOMPROMISE.getDatabaseValue(),
                certificateStatus.revocationReason);
        assertEquals("Certificate revocation date was incorrectly imported.", new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT).parse("2015.05.04-10:15"),
                certificateStatus.revocationDate);
    }
    
}
