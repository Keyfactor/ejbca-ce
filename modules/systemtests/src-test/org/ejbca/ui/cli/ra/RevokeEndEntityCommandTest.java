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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import javax.ejb.RemoveException;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
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
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for RA revokeendentity and unrevokeendentity commands
 * 
 * @version $Id$
 */
public class RevokeEndEntityCommandTest extends CaTestCase {

    private static final String USER_NAME = "RevokeEndEntityCommandTest_user1";
    private static final String[] HAPPY_PATH_REVOKE_ONHOLD_ARGS = { USER_NAME, String.valueOf(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) };

    private int caid = getTestCAId();

    private RevokeEndEntityCommand command0;
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("RevokeEndEntityCommandTest"));

    private EndEntityManagementSessionRemote eeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Before
    public void setUp() throws Exception {
        super.setUp();
        command0 = new RevokeEndEntityCommand();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    @Test
    public void testExecuteHappyPath() throws EndEntityExistsException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException, IllegalQueryException, RemoveException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, CustomCertificateSerialNumberException, IllegalKeyException, CertificateCreateException,
            CesecoreException, CertificateExtensionException {

        String fingerprint = null;
        try {
            assertFalse(eeSession.existsUser(USER_NAME));
            final EndEntityInformation userdata = new EndEntityInformation(USER_NAME, "C=SE, O=PrimeKey, CN=" + USER_NAME, caid, null, null,
                    EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, new Date(), new Date(),
                    SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            eeSession.addUser(admin, userdata, false);
            assertTrue(eeSession.existsUser(USER_NAME));
            
            // Create a certificate for the user
            KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), userdata.getUsername(), userdata.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, userdata, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate)resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            CertificateInfo info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals(CertificateConstants.CERT_ACTIVE, info.getStatus());
            
            // Revoke user, will change status of certificate and user
            command0.execute(HAPPY_PATH_REVOKE_ONHOLD_ARGS);
            final Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, USER_NAME);
            final String caauthstring = null;
            final String eeprofilestr = null;
            Collection<EndEntityInformation> col = eeSession.query(admin, query, caauthstring, eeprofilestr, 0, AccessRulesConstants.REVOKE_END_ENTITY);
            assertEquals(1, col.size());
            EndEntityInformation eei = col.iterator().next();
            assertEquals("CN="+USER_NAME+",O=PrimeKey,C=SE", eei.getDN());
            assertEquals(EndEntityConstants.STATUS_REVOKED, eei.getStatus());
            info = certificateStoreSession.getCertificateInfo(fingerprint);
            assertEquals(CertificateConstants.CERT_REVOKED, info.getStatus());
            assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, info.getRevocationReason());
        } finally {
            /// remove the user's certificate from database
            internalCertStoreSession.removeCertificate(fingerprint);
            try {
                eeSession.deleteUser(admin, USER_NAME);
            } catch (NotFoundException e) {} // NOPMD: user does not exist, some error failed above           
        }  
    }

}
