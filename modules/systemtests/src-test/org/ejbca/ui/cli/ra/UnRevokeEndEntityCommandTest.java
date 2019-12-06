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
package org.ejbca.ui.cli.ra;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Date;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @version $Id$
 *
 */
public class UnRevokeEndEntityCommandTest {

    private static final String TESTCLASS_NAME = KeyRecoveryNewestCommandTest.class.getSimpleName();
    private static final String END_ENTITY_SUBJECT_DN = "C=SE, O=PrimeKey, CN=" + TESTCLASS_NAME;

    private UnRevokeEndEntityCommand command = new UnRevokeEndEntityCommand();

    private final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateCreateSessionRemote.class);
    private final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateStoreSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(TESTCLASS_NAME));

    private static X509CA x509ca = null;
    private Certificate certificate;

    private final EndEntityInformation userdata;
    
    {
        userdata = new EndEntityInformation(TESTCLASS_NAME, END_ENTITY_SUBJECT_DN, x509ca.getCAId(), null, null, EndEntityConstants.STATUS_NEW,
                new EndEntityType(EndEntityTypes.ENDUSER), EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
        userdata.setPassword("foo123");
    }
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCAWithSoftCryptoToken(authenticationToken, "C=SE,CN=" + TESTCLASS_NAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (x509ca != null) {
            CaTestUtils.removeCa(authenticationToken, x509ca.getCAInfo());
        }
    }

    @Before
    public void setup() throws Exception {

        endEntityManagementSession.addUser(authenticationToken, userdata, true);
        if (null == endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            throw new RuntimeException("Could not create end entity.");
        }    
    }

    @After
    public void tearDown() throws Exception {
        if (null != endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME)) {
            endEntityManagementSession.deleteUser(authenticationToken, TESTCLASS_NAME);
        }
        for (Certificate certificate : EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(TESTCLASS_NAME))) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
    }

    @Test
    public void testUnrevokeEndEntity()
            throws AuthorizationDeniedException, CertificateRevokeException, ApprovalException, AlreadyRevokedException, NoSuchEndEntityException,
            WaitingForApprovalException, InvalidAlgorithmParameterException, CustomCertificateSerialNumberException, IllegalKeyException,
            CADoesntExistsException, CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), userdata.getUsername(), userdata.getPassword());
        certificate = certificateCreateSession.createCertificate(authenticationToken, userdata, req, X509ResponseMessage.class,
                signSession.fetchCertGenParams()).getCertificate();
        endEntityManagementSession.revokeUser(authenticationToken, TESTCLASS_NAME, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
        if (!certificateStoreSession.isRevoked(x509ca.getSubjectDN(), CertTools.getSerialNumber(certificate))) {
            throw new RuntimeException("Certificate was not revoked, can't continue test.");
        }
        final String args[] = new String[] { TESTCLASS_NAME };
        command.execute(args);
        assertFalse("Certificate was not unrevoked.",
                certificateStoreSession.isRevoked(x509ca.getSubjectDN(), CertTools.getSerialNumber(certificate)));
        assertEquals("End entity was not set to generated.", EndEntityConstants.STATUS_GENERATED,
                endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME).getStatus());
    }
    
    //Test unrevoking an end entity with a reason other than hold
    @Test
    public void testUnrevokeEndEntityNotSetToHold()
            throws AuthorizationDeniedException, CertificateRevokeException, ApprovalException, AlreadyRevokedException, NoSuchEndEntityException,
            WaitingForApprovalException, InvalidAlgorithmParameterException, CustomCertificateSerialNumberException, IllegalKeyException,
            CADoesntExistsException, CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateExtensionException {
        KeyPair keys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), userdata.getUsername(), userdata.getPassword());
        certificate = certificateCreateSession.createCertificate(authenticationToken, userdata, req, X509ResponseMessage.class,
                signSession.fetchCertGenParams()).getCertificate();
        endEntityManagementSession.revokeUser(authenticationToken, TESTCLASS_NAME, RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE);
        if (!certificateStoreSession.isRevoked(x509ca.getSubjectDN(), CertTools.getSerialNumber(certificate))) {
            throw new RuntimeException("Certificate was not revoked, can't continue test.");
        }
        final String args[] = new String[] { TESTCLASS_NAME };
        command.execute(args);
        assertTrue("Certificate was incorrectly unrevoked.",
                certificateStoreSession.isRevoked(x509ca.getSubjectDN(), CertTools.getSerialNumber(certificate)));
        assertEquals("End entity was not kept revoked.", EndEntityConstants.STATUS_REVOKED,
                endEntityAccessSession.findUser(authenticationToken, TESTCLASS_NAME).getStatus());
    }
       
}
