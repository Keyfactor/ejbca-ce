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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

import org.bouncycastle.asn1.x509.ReasonFlags;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaImportCRLCommand
 * 
 * @version $Id$
 */
public class CaImportCRLCommandTest {

    private static final String CA_NAME = "4711CRL";
    private static final String CRL_FILENAME = "4711CRL.crl";
    private static final String CA_DN = "CN=CLI Test CA 4711CRL,O=EJBCA,C=SE";
    private static final String[] CAINIT_ARGS = { CA_NAME, "\""+CA_DN+"\"", "soft", "foo123", "1024", "RSA",
            "365", "null", "SHA1WithRSA" };
    private static final String[] CACREATECRL_ARGS = { CA_NAME };
    private static final String[] CAGETCRL_ARGS = { CA_NAME, CRL_FILENAME };
    private static final String[] CAIMPORTCRL_STRICT_ARGS = { CA_NAME, CRL_FILENAME, "STRICT" };
    private static final String[] CAIMPORTCRL_LENIENT_ARGS = { CA_NAME, CRL_FILENAME, "LENIENT" };
    private static final String[] CAIMPORTCRL_ADAPTIVE_ARGS = { CA_NAME, CRL_FILENAME, "ADAPTIVE" };

    private CaInitCommand caInitCommand;
    private CaCreateCrlCommand caCreateCrlCommand;
    private CaGetCrlCommand caGetCrlCommand;
    private CaImportCRLCommand caImportCrlCommand;
    
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaImportCRLCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CrlStoreSessionRemote crlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CertificateRequestSessionRemote certReqSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateRequestSessionRemote.class);
    private CertificateStoreSessionRemote certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        caInitCommand = new CaInitCommand();
        caCreateCrlCommand = new CaCreateCrlCommand();
        caGetCrlCommand = new CaGetCrlCommand();
        caImportCrlCommand = new CaImportCRLCommand();
        
        try {
            File f = new File(CRL_FILENAME);
            if (f.exists()) {
                f.delete();
            }
            cleanUp();
        } catch (Exception e) {
            // Ignore.

        }
    }

    @After
    public void tearDown() throws Exception {
        File f = new File(CRL_FILENAME);
        f.deleteOnExit();
    }

    /**
     * Test trivial happy path for execute, i.e, create an ordinary CA.
     * 
     * @throws Exception on serious error
     */
    @Test
    public void testCreateAndImportCRL() throws Exception {
        String fingerprint = null;
        final String testUsername = "4711CRLUSER";
        try {
            caInitCommand.execute(CAINIT_ARGS);
            assertNotNull("Test CA was not created.", caSession.getCAInfo(admin, CA_NAME));
            CAInfo cainfo = caSession.getCAInfo(admin, CA_NAME);
            int no = crlSession.getLastCRLNumber(cainfo.getSubjectDN(), false);
            caCreateCrlCommand.execute(CACREATECRL_ARGS);
            int noafter = crlSession.getLastCRLNumber(cainfo.getSubjectDN(), false);
            assertEquals("A new CRL was not created", no+1, noafter);
            File f = new File(CRL_FILENAME);
            assertFalse("CRL file already exists.", f.exists());
            caGetCrlCommand.execute(CAGETCRL_ARGS);
            assertTrue("Get CRL command failed, no file exists.", f.exists());
            // Now create a certificate that we can play with and run the commands
            EndEntityInformation userdata = new EndEntityInformation(testUsername, "CN=4711CRLUSER", cainfo.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            byte[] p12 = certReqSession.processSoftTokenReq(admin, userdata, null, "512", "RSA", true);
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new ByteArrayInputStream(p12), userdata.getPassword().toCharArray());
            assertNotNull(keyStore);
            Enumeration<String> aliases = keyStore.aliases();
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            if (CertTools.isSelfSigned(cert)) {
                // Ignore the CA cert and get another one
                alias = aliases.nextElement();
                cert = keyStore.getCertificate(alias);
            }
            assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
                    CertTools.getSubjectDN(cert), userdata.getDN());
            fingerprint = CertTools.getFingerprintAsString(cert);
            CertificateInfo info = certStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Cert should not be revoked", info.getStatus(), CertificateConstants.CERT_ACTIVE);
            caImportCrlCommand.execute(CAIMPORTCRL_STRICT_ARGS);
            caImportCrlCommand.execute(CAIMPORTCRL_LENIENT_ARGS);
            caImportCrlCommand.execute(CAIMPORTCRL_ADAPTIVE_ARGS);
            // Nothing should have happened to the certificate
            info = certStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Cert should not be revoked", info.getStatus(), CertificateConstants.CERT_ACTIVE);
            // Now revoke the certificate, create a new CRL and import it, nothing should happen still
            internalCertStoreSession.setRevokeStatus(admin, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            caCreateCrlCommand.execute(CACREATECRL_ARGS);
            caGetCrlCommand.execute(CAGETCRL_ARGS);
            caImportCrlCommand.execute(CAIMPORTCRL_STRICT_ARGS);
            caImportCrlCommand.execute(CAIMPORTCRL_LENIENT_ARGS);
            caImportCrlCommand.execute(CAIMPORTCRL_ADAPTIVE_ARGS);
            info = certStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Cert should be revoked", info.getStatus(), CertificateConstants.CERT_REVOKED);
            assertEquals("Revocation reasonn should be on hold", info.getRevocationReason(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            // Now unrevoke the certificate and import the CRL, it should be revoked again
            internalCertStoreSession.setRevokeStatus(admin, cert, new Date(), RevokedCertInfo.NOT_REVOKED);
            info = certStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Cert should not be revoked", info.getStatus(), CertificateConstants.CERT_ACTIVE);
            // Strict will do it
            caImportCrlCommand.execute(CAIMPORTCRL_STRICT_ARGS);
            info = certStoreSession.getCertificateInfo(fingerprint);
            assertEquals("Cert should be revoked", CertificateConstants.CERT_REVOKED, info.getStatus());
            assertEquals("Revocation reason should be on hold", info.getRevocationReason(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            // Now delete the certificate from the database an import the CRL, using ADAPTIVE a new certificate is created
            Certificate cert2 = certStoreSession.findCertificateByIssuerAndSerno(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertNotNull("Certificate should exist", cert2);
            internalCertStoreSession.removeCertificate(fingerprint);
            cert2 = certStoreSession.findCertificateByIssuerAndSerno(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertNull("Certificate should not exist", cert2);
            caImportCrlCommand.execute(CAIMPORTCRL_STRICT_ARGS);
            // Strict should not do anything because the cert does not exist
            cert2 = certStoreSession.findCertificateByIssuerAndSerno(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertNull("Certificate should not exist", cert2);
            // Lenient should not do anything because the cert does not exist
            caImportCrlCommand.execute(CAIMPORTCRL_LENIENT_ARGS);
            cert2 = certStoreSession.findCertificateByIssuerAndSerno(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertNull("Certificate should not exist", cert2);
            // Adaptive should do something because a dummy cert will be created
            caImportCrlCommand.execute(CAIMPORTCRL_ADAPTIVE_ARGS);
            cert2 = certStoreSession.findCertificateByIssuerAndSerno(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertNotNull("Certificate should exist", cert2);
            fingerprint = CertTools.getFingerprintAsString(cert2);
        } finally {
            cleanUp();
            endEntityManagementSession.revokeAndDeleteUser(admin, testUsername, ReasonFlags.unused);
            endEntityManagementSession.revokeAndDeleteUser(admin, CaImportCRLCommand.MISSING_USERNAME_PREFIX+CA_NAME, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

    private void cleanUp() throws Exception {
        CaTestCase.removeTestCA(CA_NAME);
    }
}
