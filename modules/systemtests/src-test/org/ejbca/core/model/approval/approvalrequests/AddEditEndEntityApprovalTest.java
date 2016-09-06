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

package org.ejbca.core.model.approval.approvalrequests;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class AddEditEndEntityApprovalTest  extends CaTestCase {

    
    //private static final Logger log = Logger.getLogger(AddEditEndEntityApprovalTest.class);
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AddEditEndEntityApprovalTest"));
    
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);

    private int caid = getTestCAId();
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }
    
    @Before
    public void setUp() throws Exception {
        super.setUp();
    }
    
    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }
    
    @Test
    public void test01testEndEntityExtendedInformation() throws Exception {
        String username = "test01extendedInfoUser";
        
        // make sure that the end entity we are testing with does not already exist
        if(endEntityAccessSession.findUser(internalAdmin, username) != null) {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        }
        
        try {

            // Create a simple approval profile to test with
            final String approvalProfileName = AddEditEndEntityApprovalTest.class.getSimpleName() + "_AccumulativeApprovalProfile";
            final ApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);

            // Add an end entity through executing an AddEndEntityApprovalRequest
            EndEntityInformation userdata = new EndEntityInformation(username, "CN=" + username, caid, null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.TOKEN_SOFT_P12, 0, null);
            userdata.setPassword("foo123");
            userdata.setStatus(EndEntityConstants.STATUS_NEW);
            AddEndEntityApprovalRequest addAr = new AddEndEntityApprovalRequest(userdata, true, internalAdmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, approvalProfile);
            addAr.execute(endEntityManagementSession, 4711);

            // Verify that the end entity was added
            EndEntityInformation executeUser = endEntityAccessSession.findUser(internalAdmin, username);
            assertNotNull("Failed to execute AddEndEnitityApprovalRequest", executeUser);
            
            // Verify that the end entity contains the approval request ID of the AddEndEntityApprovalRequest
            ExtendedInformation ext = executeUser.getExtendedinformation();
            assertNotNull("Newly created end entity does not contain extended information", ext);
            Integer addEEReqId = ext.getAddEndEntityApprovalRequestId();
            assertNotNull("Extended information does not contain the AddEndEntityApprovalRequestID", addEEReqId);
            assertEquals(Integer.valueOf(4711), addEEReqId);
            
            // Edit the end entity through executing an EditEndEntityApprovalRequest
            EndEntityInformation editUserdata = userdata;
            assertEquals("CN=" + username, userdata.getDN());
            editUserdata.setDN("CN=" + username + ", C=SE");
            EditEndEntityApprovalRequest editAr = new EditEndEntityApprovalRequest(editUserdata, true, userdata, internalAdmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, approvalProfile); 
            editAr.execute(endEntityManagementSession, 4712);
            
            // Verify the the end entity has been edited
            executeUser = endEntityAccessSession.findUser(internalAdmin, username);
            assertNotNull("Somehow, the test end entity just disappeared", executeUser);
            assertEquals("CN=" + username + ",C=SE", executeUser.getDN());
            
            // Verify that the end entity contains the approval request ID of the AddEndEntityApprovalRequest and the EditEndEntityApprovalRequest
            ext = executeUser.getExtendedinformation();
            assertNotNull("Newly edited end entity does not contain extended information", ext);
            addEEReqId = ext.getAddEndEntityApprovalRequestId();
            assertNotNull("Extended information does not contain the AddEndEntityApprovalRequestID", addEEReqId);
            assertEquals(Integer.valueOf(4711), addEEReqId);
            List<Integer> editEEReqIds = ext.getEditEndEntityApprovalRequestIds();
            assertNotNull("Extended information does not contain the EditEndEntityApprovalRequestIDs", editEEReqIds);
            assertEquals(1, editEEReqIds.size());
            assertEquals(Integer.valueOf(4712), editEEReqIds.get(0));

            // Change the status of the end entity through executing a ChangeStatusEndEntityApprovalRequest
            assertEquals(EndEntityConstants.STATUS_NEW, executeUser.getStatus());
            ChangeStatusEndEntityApprovalRequest statusAr = new ChangeStatusEndEntityApprovalRequest(username, EndEntityConstants.STATUS_NEW, EndEntityConstants.STATUS_GENERATED, internalAdmin, null, caid, SecConst.EMPTY_ENDENTITYPROFILE, approvalProfile);
            statusAr.execute(endEntityManagementSession, endEntityAccessSession, 4713);
            
            // Verify that the end entity status has been changed
            executeUser = endEntityAccessSession.findUser(internalAdmin, username);
            assertNotNull("Somehow, the test end entity just disappeared", executeUser);
            assertEquals(EndEntityConstants.STATUS_GENERATED, executeUser.getStatus());
            
            // Verify that the end entity contains the approval request ID of the AddEndEntityApprovalRequest and the EditEndEntityApprovalRequest 
            // and ChangeStatusEndEntityApprovalRequest
            ext = executeUser.getExtendedinformation();
            assertNotNull("Newly edited end entity does not contain extended information", ext);
            addEEReqId = ext.getAddEndEntityApprovalRequestId();
            assertNotNull("Extended information does not contain the AddEndEntityApprovalRequestID", addEEReqId);
            assertEquals(Integer.valueOf(4711), addEEReqId);
            editEEReqIds = ext.getEditEndEntityApprovalRequestIds();
            assertNotNull("Extended information does not contain the EditEndEntityApprovalRequestIDs", editEEReqIds);
            assertEquals(2, editEEReqIds.size());
            assertTrue("Extended information does not contain the EditEndEntityApprovalRequestID", editEEReqIds.contains(Integer.valueOf(4712)));
            assertTrue("Extended information does not contain the ChangeStatusEndEntityApprovalRequestID", editEEReqIds.contains(Integer.valueOf(4713)));

        } finally {
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }
        }
    }
    
    
    
    @Override
    public String getRoleName() {
        return "AddEditEndEntityApprovalTest";
    }

}
