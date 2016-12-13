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

import java.util.List;

import javax.ejb.RemoveException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class EndEntityAccessSessionTest extends CaTestCase {
    
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);

    private AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(getRoleName());
    
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
     * @throws UserDoesntFullfillEndEntityProfile 
     * @throws EndEntityExistsException 
     * @throws RemoveException 
     * @throws CertificateSerialNumberException 
     * @throws IllegalNameException 
     * @throws ApprovalException 
     * @throws CustomFieldException 
     */
    @Test
    public void testFindUserBySubjectAndIssuerDnWithMultipleUsers() throws CADoesntExistsException, AuthorizationDeniedException,
            EndEntityExistsException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, NoSuchEndEntityException, RemoveException,
            IllegalNameException, CertificateSerialNumberException, CustomFieldException, ApprovalException {
        String commonDn = "CN=foo";
        String firstUsername = "alpha";
        String secondUsername = "beta";
        String issuerDn = CertTools.getIssuerDN(getTestCACert());
        int caid = getTestCAId();
        EndEntityInformation firstUser = new EndEntityInformation(firstUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
        firstUser.setPassword("foo");
        EndEntityInformation secondUser = new EndEntityInformation(secondUsername, commonDn, caid, "", "", new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, null);
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

}
