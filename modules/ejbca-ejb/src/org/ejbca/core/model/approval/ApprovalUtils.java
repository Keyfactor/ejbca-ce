package org.ejbca.core.model.approval;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;

public class ApprovalUtils {
    
    public static ApprovalProfile[] getApprovalProfiles(final int action, final CAInfo cainfo, final CertificateProfile certProfile, 
            final ApprovalProfileSession approvalProfileSession) {
            ApprovalProfile profiles[] = new ApprovalProfile[2];
            ApprovalProfile firstProfile = null;
            ApprovalProfile secondProfile = null;
            
            if(cainfo != null) {
                int approvalProfileId = cainfo.getApprovalProfile();
                if(approvalProfileId != -1) {
                    ApprovalProfile profile = approvalProfileSession.getApprovalProfile(approvalProfileId);
                    if(arrayContainsValue(profile.getActionsRequireApproval(), action)) {
                        firstProfile = profile;
                    }
                }
            }

            if(certProfile != null) {
                int approvalProfileId = certProfile.getApprovalProfileID();
                if(approvalProfileId != -1) {
                    ApprovalProfile profile = approvalProfileSession.getApprovalProfile(approvalProfileId);
                    if(arrayContainsValue(profile.getActionsRequireApproval(), action)) {
                        secondProfile = profile;
                    }
                }            
            }
            
            if(firstProfile != null && secondProfile != null) {
                if(firstProfile.equals(secondProfile)) {
                    secondProfile = null;
                } else if((firstProfile.getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) && 
                           secondProfile.getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
                    if(secondProfile.getNumberOfApprovals() > firstProfile.getNumberOfApprovals()) {
                        firstProfile = secondProfile;
                    }
                    secondProfile = null;
                }
            } else if((firstProfile==null) && (secondProfile != null)){
                firstProfile = secondProfile;
                secondProfile = null;
            }
            
            profiles[0] = firstProfile;
            profiles[1] = secondProfile;
            
            return profiles;
    }
    
    private static boolean arrayContainsValue(final int[] array, final int value) {
        for(int v : array) {
            if(v==value) {
                return true;
            }
        }
        return false;
    }
    
}
