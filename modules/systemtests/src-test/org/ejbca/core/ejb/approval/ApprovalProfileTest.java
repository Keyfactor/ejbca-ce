package org.ejbca.core.ejb.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileByAdminRoles;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.approval.ApprovalStepMetadata;
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
            assertEquals(0, addedApprovalProfile.getApprovalSteps().size());
            assertEquals(0, addedApprovalProfile.getActionsRequireApproval().length);
        } finally {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
    }
    
    @Test
    public void addApprovalByAdminRoleApprovalProfile() throws Exception {
        final String approvalProfileName = "ApprovalProfileByAdmins";
        if(approvalProfileSession.getApprovalProfile(approvalProfileName)!=null) {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
        try {
            final ApprovalProfile approvalProfile = new ApprovalProfile(approvalProfileName);
            approvalProfile.setApprovalProfileType(new ApprovalProfileByAdminRoles());
            final int id = approvalProfileSession.addApprovalProfile(ADMIN, approvalProfileName, approvalProfile);
            ApprovalProfile addedApprovalProfile = approvalProfileSession.getApprovalProfile(id);
            assertNotNull(addedApprovalProfile);
            assertTrue(addedApprovalProfile.getApprovalProfileType() instanceof ApprovalProfileByAdminRoles);
            assertEquals(0, addedApprovalProfile.getApprovalSteps().size());
            assertEquals(0, addedApprovalProfile.getNumberOfApprovals());
            assertEquals(0, addedApprovalProfile.getActionsRequireApproval().length);
        } finally {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
    }
    
    @Test
    public void addApprovalByAdminRoleApprovalProfileWithSteps() throws Exception {
        final String approvalProfileName = "ApprovalProfileByAdmins";
        if(approvalProfileSession.getApprovalProfile(approvalProfileName)!=null) {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
        try {
            final ApprovalProfile approvalProfile = new ApprovalProfile(approvalProfileName);
            final ApprovalProfileByAdminRoles adminsProfileType = new ApprovalProfileByAdminRoles();
            approvalProfile.setApprovalProfileType(adminsProfileType);
            
            final Map<Integer, String> mainObjectOptions = adminsProfileType.getMainAuthorizationObjectOptions();
            final Iterator<String> itr = mainObjectOptions.values().iterator();
            final String step1Object = itr.next();
            final String step2Object = itr.next();
            final String step3Object = step1Object;
            
            ArrayList<String> options = new ArrayList<String>();
            options.add("Option1");
            options.add("Option2");
            options.add("Option3");
            
            ArrayList<ApprovalStepMetadata> stepMetadata = new ArrayList<ApprovalStepMetadata>();
            stepMetadata.add(new ApprovalStepMetadata(1, "Instruction 1 of step 1", options, ApprovalStepMetadata.METADATATYPE_CHECKBOX));
            stepMetadata.add(new ApprovalStepMetadata(2, "Instruction 2 of step 1", options, ApprovalStepMetadata.METADATATYPE_RADIOBUTTON));
            ApprovalStep step = new ApprovalStep(1, step1Object, stepMetadata, 1, false, "test1@email.com", new ArrayList<Integer>());
            approvalProfile.addApprovalStep(step);
            
            stepMetadata = new ArrayList<ApprovalStepMetadata>();
            stepMetadata.add(new ApprovalStepMetadata(1, "Instruction 1 of step 2", options, ApprovalStepMetadata.METADATATYPE_RADIOBUTTON));
            stepMetadata.add(new ApprovalStepMetadata(2, "Instruction 2 of step 2", new ArrayList<String>(), ApprovalStepMetadata.METADATATYPE_TEXTBOX));
            ArrayList<Integer> dependentOn = new ArrayList<Integer>();
            dependentOn.add(1);
            step = new ApprovalStep(2, step2Object, stepMetadata, 5, true, "test2@email.com", dependentOn);
            approvalProfile.addApprovalStep(step);

            stepMetadata = new ArrayList<ApprovalStepMetadata>();
            stepMetadata.add(new ApprovalStepMetadata(1, "Instruction of step 3", new ArrayList<String>(), ApprovalStepMetadata.METADATATYPE_TEXTBOX));
            step = new ApprovalStep(3, step3Object, stepMetadata, 2, false, "test3@email.com", dependentOn);
            approvalProfile.addApprovalStep(step);
            
            final int id = approvalProfileSession.addApprovalProfile(ADMIN, approvalProfileName, approvalProfile);
            ApprovalProfile addedApprovalProfile = approvalProfileSession.getApprovalProfile(id);
            assertNotNull(addedApprovalProfile);
            assertEquals(3, addedApprovalProfile.getApprovalSteps().size());
            assertEquals(0, addedApprovalProfile.getNumberOfApprovals());
            
            Map<Integer, ApprovalStep> profileSteps = addedApprovalProfile.getApprovalSteps();
            step = profileSteps.get(1);
            assertEquals(step1Object, step.getStepAuthorizationObject());
            Collection<ApprovalStepMetadata> stepMd = step.getMetadata();
            assertEquals(2, stepMd.size());
            Iterator<ApprovalStepMetadata> mdItr = stepMd.iterator();
            ApprovalStepMetadata md = mdItr.next();
            assertEquals("Instruction 2 of step 1", md.getInstruction());
            assertEquals(3, md.getOptions().size());
            assertEquals("Option2", md.getOptions().get(1));
            assertEquals(ApprovalStepMetadata.METADATATYPE_RADIOBUTTON, md.getOptionsType());
            assertEquals("", md.getOptionValue());
            assertEquals("", md.getOptionNote());
            md = mdItr.next();
            assertEquals("Instruction 1 of step 1", md.getInstruction());
            assertEquals(3, md.getOptions().size());
            assertEquals("Option1", md.getOptions().get(0));
            assertEquals(ApprovalStepMetadata.METADATATYPE_CHECKBOX, md.getOptionsType());
            assertEquals("", md.getOptionValue());
            assertEquals("", md.getOptionNote());
            assertEquals(1, step.getRequiredNumberOfApproval());
            assertFalse(step.canSeePreviousSteps());
            assertEquals("test1@email.com", step.getNotificationEmail());
            assertEquals(0, step.getPreviousStepsDependency().size());
            
            
            step = profileSteps.get(2);
            assertEquals(step2Object, step.getStepAuthorizationObject());
            stepMd = step.getMetadata();
            assertEquals(2, stepMd.size());
            mdItr = stepMd.iterator();
            md = mdItr.next();
            assertEquals("Instruction 2 of step 2", md.getInstruction());
            assertEquals(0, md.getOptions().size());
            assertEquals(ApprovalStepMetadata.METADATATYPE_TEXTBOX, md.getOptionsType());
            assertEquals("", md.getOptionValue());
            assertEquals("", md.getOptionNote());
            md = mdItr.next();
            assertEquals("Instruction 1 of step 2", md.getInstruction());
            assertEquals(3, md.getOptions().size());
            assertEquals("Option3", md.getOptions().get(2));
            assertEquals(ApprovalStepMetadata.METADATATYPE_RADIOBUTTON, md.getOptionsType());
            assertEquals("", md.getOptionValue());
            assertEquals("", md.getOptionNote());
            assertEquals(5, step.getRequiredNumberOfApproval());
            assertTrue(step.canSeePreviousSteps());
            assertEquals("test2@email.com", step.getNotificationEmail());
            assertEquals(1, step.getPreviousStepsDependency().size());
            assertEquals(new Integer(1), step.getPreviousStepsDependency().get(0));

            step = profileSteps.get(3);
            assertEquals(step3Object, step.getStepAuthorizationObject());
            stepMd = step.getMetadata();
            assertEquals(1, stepMd.size());
            md = stepMd.iterator().next();
            assertEquals("Instruction of step 3", md.getInstruction());
            assertEquals(0, md.getOptions().size());
            assertEquals(ApprovalStepMetadata.METADATATYPE_TEXTBOX, md.getOptionsType());
            assertEquals("", md.getOptionValue());
            assertEquals("", md.getOptionNote());
            assertEquals(2, step.getRequiredNumberOfApproval());
            assertFalse(step.canSeePreviousSteps());
            assertEquals("test3@email.com", step.getNotificationEmail());
            assertEquals(1, step.getPreviousStepsDependency().size());
            assertEquals(new Integer(1), step.getPreviousStepsDependency().get(0));
            
        } finally {
            approvalProfileSession.removeApprovalProfile(ADMIN, approvalProfileName);
        }
    }

    
}
