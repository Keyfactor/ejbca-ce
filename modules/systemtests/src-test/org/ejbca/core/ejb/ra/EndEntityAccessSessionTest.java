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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
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

/**
 * @version $Id$
 *
 */
public class EndEntityAccessSessionTest extends CaTestCase {
    
    private static final Logger log = Logger.getLogger(EndEntityAccessSessionTest.class);

    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);

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
     * @throws AuthorizationDeniedException 
     * @throws CADoesntExistsException 
     * @throws EjbcaException 
     * @throws WaitingForApprovalException 
     * @throws EndEntityProfileValidationException 
     * @throws EndEntityExistsException 
     * @throws RemoveException 
     * @throws CertificateSerialNumberException 
     * @throws IllegalNameException 
     * @throws ApprovalException 
     * @throws CustomFieldException 
     */
    @Test
    public void testFindUserBySubjectAndIssuerDnWithMultipleUsers() throws CADoesntExistsException, AuthorizationDeniedException,
            EndEntityExistsException, EndEntityProfileValidationException, WaitingForApprovalException, NoSuchEndEntityException, RemoveException,
            IllegalNameException, CertificateSerialNumberException, CustomFieldException, ApprovalException {
        String commonDn = "CN=foo";
        String firstUsername = "alpha";
        String secondUsername = "beta";
        String issuerDn = CertTools.getIssuerDN(getTestCACert());
        int caid = getTestCAId();
        EndEntityInformation firstUser = new EndEntityInformation(firstUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        firstUser.setPassword("foo");
        EndEntityInformation secondUser = new EndEntityInformation(secondUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
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
            WaitingForApprovalException, IllegalQueryException, NoSuchEndEntityException, RemoveException {
        String username = "testQueryUser";
        String password = "foo123";
        int caid = getTestCAId();
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, username, password, "C=SE, O=AnaTom, CN=" + username, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, caid);
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
            EndEntityProfileValidationException, WaitingForApprovalException, IllegalQueryException, NoSuchEndEntityException, RemoveException,
            CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmException {
        String firstUser = "foo";
        String secondUser = "bar";
        String caName = "testQueryUserWithCAandEEPRestrictions";
        String password = "foo123";
        int otherCaId = getTestCAId();
        createTestCA(caName);
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, firstUser, password, "C=SE, CN=" + firstUser, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, getTestCAId(caName));
        //Create a second user from a different CA just to verify
        endEntityManagementSessionRemote.addUser(alwaysAllowToken, secondUser, password, "C=SE, CN=" + secondUser, null, null, true,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0, otherCaId);
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

}
