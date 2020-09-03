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
package org.ejbca.core.ejb.ra;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * @version $Id$
 *
 */
public class EndEntityAccessSessionTest extends CaTestCase {
    
    private static final Logger log = Logger.getLogger(EndEntityAccessSessionTest.class);

    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(getRoleName());
    
    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };
        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };
    
    @Before
    public void setup() throws Exception {
        super.setUp();
    }
    
    @After
    public void teardown() throws Exception {
        super.tearDown();
    }
    
    /**
     * This test tests the method findUserBySubjectAndIssuerDN with multiple
     * users that share the same DN. 
     */
    @Test
    public void testFindUserBySubjectAndIssuerDnWithMultipleUsers() throws CADoesntExistsException, AuthorizationDeniedException,
            EndEntityExistsException, EndEntityProfileValidationException, WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException,
            IllegalNameException, CertificateSerialNumberException, CustomFieldException, ApprovalException {
        String commonDn = "CN=foo";
        String firstUsername = "alpha";
        String secondUsername = "beta";
        String issuerDn = CertTools.getIssuerDN(getTestCACert());
        int caid = getTestCAId();
        EndEntityInformation firstUser = new EndEntityInformation(firstUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        firstUser.setPassword("foo");
        EndEntityInformation secondUser = new EndEntityInformation(secondUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, null);
        secondUser.setPassword("foo");
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, firstUser, false);
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, secondUser, false);
        try {
           List<EndEntityInformation> result = endEntityAccessSession.findUserBySubjectAndIssuerDN(alwaysAllowToken, commonDn, issuerDn);
           assertEquals("Two results were expected", 2, result.size());
        } finally {
            endEntityManagementSessionRemote.deleteUser(alwaysAllowToken, firstUsername);
            endEntityManagementSessionRemote.deleteUser(alwaysAllowToken, secondUsername);
        }
        
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
    
    /**
     * Tests the query function
     * 
     */
    @Test
    public void testQueryUser() throws CADoesntExistsException, EndEntityExistsException, CustomFieldException, IllegalNameException,
            ApprovalException, CertificateSerialNumberException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, IllegalQueryException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        String username = "testQueryUser";
        String password = "foo123";
        int caid = getTestCAId();
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, username, password, "C=SE, O=AnaTom, CN=" + username, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, caid);
        try {
            Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_USERNAME, BasicMatch.MATCH_TYPE_EQUALS, username);
            String caauthstring = null;
            String eeprofilestr = null;
            Collection<EndEntityInformation> col = endEntityAccessSession.query(alwaysAllowToken, query, caauthstring, eeprofilestr, 0,
                    AccessRulesConstants.VIEW_END_ENTITY);
            assertEquals("The number of results were other than 1.", 1, col.size());
        } finally {
            endEntityManagementSessionRemote.deleteUser(alwaysAllowToken, username);
        }
    }
    
    /**
     * Tests the query function with restrictions set on CAs and EEP
     * 
     */
    @Test
    public void testQueryUserWithCAandEEPRestrictions() throws CADoesntExistsException, EndEntityExistsException, CustomFieldException,
            IllegalNameException, ApprovalException, CertificateSerialNumberException, AuthorizationDeniedException,
            EndEntityProfileValidationException, WaitingForApprovalException, IllegalQueryException, NoSuchEndEntityException, CouldNotRemoveEndEntityException,
            CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        String firstUser = "foo";
        String secondUser = "bar";
        String caName = "testQueryUserWithCAandEEPRestrictions";
        String password = "foo123";
        int otherCaId = getTestCAId();
        createTestCA(caName);
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, firstUser, password, "C=SE, CN=" + firstUser, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, getTestCAId(caName));
        //Create a second user from a different CA just to verify
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, secondUser, password, "C=SE, CN=" + secondUser, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, otherCaId);
        try {
            Query query = new Query(Query.TYPE_USERQUERY);
            query.add(UserMatch.MATCH_WITH_COMMONNAME, BasicMatch.MATCH_TYPE_BEGINSWITH, firstUser);
            query.add(UserMatch.MATCH_WITH_COMMONNAME, BasicMatch.MATCH_TYPE_BEGINSWITH, secondUser, Query.CONNECTOR_OR);
            String caauthstring = "caId = " + String.valueOf(getTestCAId());
            String eeprofilestr = "endEntityProfileId = " + String.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            List<EndEntityInformation> result = new ArrayList<>( endEntityAccessSession.query(alwaysAllowToken, query, caauthstring, eeprofilestr, 0,
                    AccessRulesConstants.VIEW_END_ENTITY));
            assertEquals("The number of results were other than 1.", 1,result.size());
            assertEquals("The wrong end entity was returned.", secondUser, result.get(0).getUsername());
        } finally {
            endEntityManagementSessionRemote.deleteUser(alwaysAllowToken, firstUser);
            endEntityManagementSessionRemote.deleteUser(alwaysAllowToken, secondUser);
            removeTestCA(caName);
        }
    }

    @Test
    public void testFindCertificatesByUsername() throws Exception {
        final String username = "fooFindCertificatesByUsername";
        final String caName = "testFindCertificatesByUsername";
        Certificate certificate1 = null;
        Certificate certificate2 = null;
        try {
            // Create test CA and a test user.
            createTestCA(caName);
            CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, caName);
            
            endEntityManagementSessionRemote.addUser(alwaysAllowToken, username, "foo123", "C=SE, CN=" + username, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, getTestCAId(caName));
            
            // 1. Search for user with no certificates at all.
            assertFindCertificateResults(alwaysAllowToken, username, 0, 0);
            
            // 1.1 Search for user with 1 valid certificate.
            certificate1 = createCertificateForUser(alwaysAllowToken, username);
            assertFindCertificateResults(alwaysAllowToken, username, 1, 0);

            // 1.2 Search for user with 2 valid certificates.
            EndEntityInformation user = endEntityAccessSession.findUser(alwaysAllowToken, username);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSessionRemote.changeUser(alwaysAllowToken, user, false);
            certificate2 = createCertificateForUser(alwaysAllowToken, username);
            assertFindCertificateResults(alwaysAllowToken, username, 2, 0);
            // 1.3 notified about expiration is also valid.
            certificateStoreSession.setStatus(alwaysAllowToken, CertTools.getFingerprintAsString(certificate2), CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
            assertFindCertificateResults(alwaysAllowToken, username, 2, 0);
            
            // 1.4 Search for user with valid or unvalid certificates.
            endEntityManagementSessionRemote.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(certificate1), caInfo.getSubjectDN(), RevocationReasons.UNSPECIFIED.ordinal());
            assertFindCertificateResults(alwaysAllowToken, username, 2, 1);
            endEntityManagementSessionRemote.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(certificate2), caInfo.getSubjectDN(), RevocationReasons.UNSPECIFIED.ordinal());
            assertFindCertificateResults(alwaysAllowToken, username, 2, 2);
            
            // 2. Test exceptions thrown.
            AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken((X509Certificate) certificate1);
            // 2.1 Search with authorization denied view end entity profile.
            // Tbd.
            try {
                endEntityAccessSession.findCertificatesByUsername(adminTokenNoAuth, username, true, System.currentTimeMillis());
                fail( "An admin with no authorizations should not be able to call this function successfully.");
            }
            catch(AuthorizationDeniedException e) {
                assertTrue("AuthorizationDeniedException excepted.", e instanceof AuthorizationDeniedException);
            }
            // 2.2 Search with authorization denied to access this CA.
            // Tbd.
        } finally {
            internalCertificateStoreSession.removeCertificate(certificate1);
            internalCertificateStoreSession.removeCertificate(certificate2);
            try {
                endEntityManagementSessionRemote.revokeAndDeleteUser(alwaysAllowToken, username, RevocationReasons.UNSPECIFIED.ordinal());
            } catch(Exception e) {
                // NOOP
            }
            removeTestCA(caName);
        }
    }
    
    @Test
    public void testGetCertificatesBySnAndIssuer() throws Exception {
        final String username = "fooFindCertificatesBySnAndIssuer";
        final String caName = "testFindCertificatesBySnAndIssuer";
        Certificate certificate1 = null;
        try {
            // Create test CA and a test user.
            createTestCA(caName);
            CAInfo caInfo = caSession.getCAInfo(alwaysAllowToken, caName);
            
            endEntityManagementSessionRemote.addUser(alwaysAllowToken, username, "foo123", "C=SE, CN=" + username, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, getTestCAId(caName));
            
            // 1. Search for user with no certificates at all.
            CertificateWrapper result = endEntityAccessSession.getCertificate(alwaysAllowToken, "12345678ABC", caInfo.getSubjectDN());
            assertTrue("No certificate should result in no certificate found.", result == null);
            
            // 1.1 Search for user with certificate.
            certificate1 = createCertificateForUser(alwaysAllowToken, username);
            result = endEntityAccessSession.getCertificate(alwaysAllowToken, CertTools.getSerialNumberAsString(certificate1), caInfo.getSubjectDN());
            assertTrue("A certificate for the user should have been found.", result != null);
            assertEquals("And it should be the same certificate as stired for this user.", certificate1, result.getCertificate());
            
            // 2. Test exceptions thrown.
            AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken((X509Certificate) certificate1);
            // 2.1 Search with authorization denied view end entity profile.
            // Tbd: Could be improved. This simulates the missing access to the CA.
            try {
                result = endEntityAccessSession.getCertificate(adminTokenNoAuth, CertTools.getSerialNumberAsString(certificate1), caInfo.getSubjectDN());
                fail( "An admin with no authorizations should not be able to call this function successfully.");
            }
            catch(AuthorizationDeniedException e) {
                assertTrue("AuthorizationDeniedException excepted.", e instanceof AuthorizationDeniedException);
            }
            // 2.2 Search for a non existing CA.
            try {
                result = endEntityAccessSession.getCertificate(alwaysAllowToken, CertTools.getSerialNumberAsString(certificate1), "CN=fantasyCA_123");
                fail( "An admin with no authorizations should not be able to call this function successfully.");
            }
            catch(CADoesntExistsException e) {
                assertTrue("CADoesntExistsException excepted.", e instanceof CADoesntExistsException);
            }
        } finally {
            internalCertificateStoreSession.removeCertificate(certificate1);
            try {
                endEntityManagementSessionRemote.revokeAndDeleteUser(alwaysAllowToken, username, RevocationReasons.UNSPECIFIED.ordinal());
            } catch(Exception e) {
                // NOOP
            }
            removeTestCA(caName);
        }
    }
    
    
    private void assertFindCertificateResults(final AuthenticationToken admin, final String username, final int valid, final int invalid) throws Exception {
        Collection<CertificateWrapper> result = endEntityAccessSession.findCertificatesByUsername(alwaysAllowToken, username, false, System.currentTimeMillis());
        assertEquals("Certificate search for user with " + valid + " certificate(s) should return a collection with " + valid + " item(s) (valid=false).", valid , result.size());
        result = endEntityAccessSession.findCertificatesByUsername(alwaysAllowToken, username, true, System.currentTimeMillis());
        assertEquals("Certificate search for user with " + valid + " certificate(s) (" + invalid + " invalid) should return a collection with " 
             + (valid-invalid) + " item(s) (valid=true).", valid-invalid, result.size());
    }
    
    private Certificate createCertificateForUser(final AuthenticationToken admin, final String username) throws Exception {
        final Certificate result = signSession.createCertificate(admin, username, "foo123", new PublicKeyWrapper(KeyTools.genKeys("2048", "RSA").getPublic()));
        CertificateStatus status = certificateStoreSession.getStatus(CertTools.getIssuerDN(result), CertTools.getSerialNumber(result));
        assertEquals(RevokedCertInfo.NOT_REVOKED, status.revocationReason);
        return result;
    }
}
