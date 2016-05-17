package org.ejbca.core.ejb.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.junit.Test;

public class ApprovalProfileTest {

    private final AuthenticationToken ADMIN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalProfileTest"));
    
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);

    @Test
    public void addNrOfApprovalProfile() throws Exception {
        final String approvalProfileName = "nrOfApprovalProfile";
        if(approvalProfileSession.getApprovalProfile(approvalProfileName)!=null) {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
        try {
            final ApprovalProfile approvalProfile = new ApprovalProfile(approvalProfileName);
            approvalProfile.setNumberOfApprovals(2);
            final int id = approvalProfileSession.addApprovalProfile(ADMIN, approvalProfileName, approvalProfile);
            ApprovalProfile addedApprovalProfile = approvalProfileSession.getApprovalProfile(id);
            assertNotNull(addedApprovalProfile);
            assertTrue(addedApprovalProfile.getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals);
            assertEquals(2, addedApprovalProfile.getNumberOfApprovals());
        } finally {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
    }
    
}
