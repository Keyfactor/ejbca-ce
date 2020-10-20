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
package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.model.ListDataModel;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.approval.ApprovalProfileDoesNotExistException;
import org.ejbca.core.ejb.approval.ApprovalProfileExistsException;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the approval profiles page.
 *
 */
@SessionScoped
@ManagedBean(name="approvalProfilesMBean")
public class ApprovalProfilesMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -2452049885728885525L;
        
    public class ApprovalProfileGuiInfo {
        private final int id;
        private final String name;
        public ApprovalProfileGuiInfo(final int id, final String name) {
            this.name = name;
            this.id = id;
        }
        public int getId() { return this.id; }
        public String getName() { return this.name; }
    }
    
    
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    
    public ApprovalProfilesMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.APPROVALPROFILEVIEW.resource());
    }
    
    private boolean renameInProgress = false;
    private boolean deleteInProgress = false;
    private boolean addFromTemplateInProgress = false;
    private ListDataModel<ApprovalProfileGuiInfo> approvalProfilesList = null;
    private String approvalProfileName = "";
    private Integer selectedApprovalProfileId = null;
    private boolean viewOnly = true;
    
    public Integer getSelectedApprovalProfileId() {
        return selectedApprovalProfileId;
    }

    public void setSelectedApprovalProfileId(final Integer selectedApprovalProfileId) {
        this.selectedApprovalProfileId = selectedApprovalProfileId;
    }
    
    public String getSelectedApprovalProfileName() {
        final Integer profileId = getSelectedApprovalProfileId();
        if (profileId != null) {
            return approvalProfileSession.getApprovalProfileName(profileId.intValue());
        }
        return null;
    }
    
    public boolean isRenameInProgress() {
        return renameInProgress;
    }
    
    public boolean isDeleteInProgress() {
        return deleteInProgress;
    }
    
    public boolean isAddFromTemplateInProgress() {
        return addFromTemplateInProgress;
    }
    
    public boolean isOperationInProgress() {
        return isRenameInProgress() || isDeleteInProgress() || isAddFromTemplateInProgress();
    }
    
    public void selectCurrentRowData() {
        if (approvalProfilesList == null) {
            getApprovalProfiles();
        }
        final ApprovalProfileGuiInfo approvalProfileItem = approvalProfilesList.getRowData();
        selectedApprovalProfileId = approvalProfileItem.getId();
    }

    public ListDataModel<ApprovalProfileGuiInfo> getApprovalProfiles() {
        if (approvalProfilesList == null) {
            final List<ApprovalProfileGuiInfo> items = new ArrayList<>();
            final List<Integer> authorizedProfileIds = new ArrayList<>();

            authorizedProfileIds.addAll(approvalProfileSession.getAuthorizedApprovalProfileIds(getAdmin()));
            final Map<Integer, String> idToNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
            for (Integer profileId : authorizedProfileIds) {
                final String name = idToNameMap.get(profileId);
                items.add(new ApprovalProfileGuiInfo(profileId, name));
            }
            // Sort list by name
            Collections.sort(items, new Comparator<ApprovalProfileGuiInfo>() {
                @Override
                public int compare(final ApprovalProfileGuiInfo a, final ApprovalProfileGuiInfo b) {
                    return a.getName().compareToIgnoreCase(b.getName());
                }
            });
            approvalProfilesList = new ListDataModel<>(items);
        }
        return approvalProfilesList;
    }
    
    public String getResetApprovalProfilesTrigger() {
        approvalProfilesList = null;
        return "";
    }
    
    public boolean isAuthorizedToEdit() {
        return isAuthorizedTo(StandardRules.APPROVALPROFILEEDIT.resource());
    }
    
    public String getApprovalProfileName() {
        return approvalProfileName;
    }

    public void setApprovalProfileName(String approvalProfileName) {
        approvalProfileName = approvalProfileName.trim();
        this.approvalProfileName = approvalProfileName;
    }
    
    public String actionView() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            viewOnly = true;
            return "view"; // Outcome is defined in faces-config.xml
        } else {
            return "";
        }
    }
    
    public String actionEdit() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            viewOnly = false;
            return "edit"; 
        } else {
            return "";
        }
    }
    
    public boolean getViewOnly() {
        return viewOnly;
    }
    
    public void actionCancel() {
        addFromTemplateInProgress = false;
        deleteInProgress = false;
        renameInProgress = false;
        approvalProfilesList = null;
        selectedApprovalProfileId = null;
        approvalProfileName = null;
    }
    

    
    
    public void actionDelete() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            deleteInProgress = true;
        }
    }
    public void actionDeleteConfirm() {
        if (canDeleteApprovalProfile()) {
            try {
                approvalProfileSession.removeApprovalProfile(getAdmin(), getSelectedApprovalProfileId());
            } catch (AuthorizationDeniedException e) {
                addNonTranslatedErrorMessage("Not authorized to remove approval profile.");
            }
        } else {
            addErrorMessage("COULDNTDELETEAPPROVALPROF");
        }
        actionCancel();
    }
    private boolean canDeleteApprovalProfile() {
        boolean ret = true;
        final int approvalProfileId = getSelectedApprovalProfileId().intValue();
        // Check if approval profile is in use by any certificate profile
        final List<String> certProfilesReferencingAP = getCertProfilesUsingApprovalProfile(approvalProfileId);
        if (!certProfilesReferencingAP.isEmpty()) {
            ret = false;
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("APPROVALPROFILEUSEDINCERTPROFILES") + " "
                        + getAsCommaSeparatedString(certProfilesReferencingAP)); 
            }
        
        // Check if approval profile is in use by a CA
        final List<String> casReferencingAP = getCAsUsingApprovalProfile(approvalProfileId);
        if (!casReferencingAP.isEmpty()) {
            ret = false;
            addNonTranslatedErrorMessage(getEjbcaWebBean().getText("APPROVALPROFILEUSEDINCAS") + " "
                    + getAsCommaSeparatedString(casReferencingAP)); 
        }
        // TODO check whether an approval profiles is referenced in a waiting approval request
        
        return ret;
    }
    public List<String> getCertProfilesUsingApprovalProfile(final int approvalProfileId) {
        final CertificateProfileSessionLocal certProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
        Map<Integer, CertificateProfile> allCertProfiles = certProfileSession.getAllCertificateProfiles();
        Set<Entry<Integer, CertificateProfile>> entries = allCertProfiles.entrySet();
        List<String> result = new ArrayList<>();
        for(Entry<Integer, CertificateProfile> entry : entries) {
            final CertificateProfile certProfile = entry.getValue();
            if(certProfile.getApprovals().containsValue(Integer.valueOf(approvalProfileId))) {
                result.add(certProfileSession.getCertificateProfileName(entry.getKey()));
            }
        }
        return result;
    }
    
    public List<String> getCAsUsingApprovalProfile(final int approvalProfileId) {
        final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
        List<Integer> allCas = caSession.getAllCaIds();
        List<String> result = new ArrayList<>();
        for (int caid : allCas) {
            CAInfo cainfo = caSession.getCAInfoInternal(caid);
            if (cainfo.getApprovals().containsValue(Integer.valueOf(approvalProfileId))) {
                result.add(cainfo.getName());
            }
        }
        return result;
    } 
    
    private String getAsCommaSeparatedString(final List<String> list) {
        final StringBuilder sb = new StringBuilder();
        for (final String entry : list) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(entry);
        }
        return sb.toString();
    }
    
    public void actionRename() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            renameInProgress = true;
        }
    }

    public void actionRenameConfirm() {
        final String approvalProfileName = getApprovalProfileName();
        if (StringUtils.isNotEmpty(approvalProfileName)) {
            if (!StringTools.checkFieldForLegalChars(approvalProfileName)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                try {
                    approvalProfileSession.renameApprovalProfile(getAdmin(), approvalProfileSession.getApprovalProfile(getSelectedApprovalProfileId()),
                            approvalProfileName);
                    setApprovalProfileName("");
                } catch (ApprovalProfileExistsException | ApprovalProfileDoesNotExistException e) {
                    addNonTranslatedErrorMessage(e);
                } catch (AuthorizationDeniedException e) {
                    addNonTranslatedErrorMessage("Not authorized to rename certificate profile.");
                }
                actionCancel();
            }
        }
    }
    
    public void actionAddFromTemplate() {
        selectCurrentRowData();
        if (selectedProfileExists()) {
            addFromTemplateInProgress = true;
        }
    }
    
    public void actionAddFromTemplateConfirm() {
        final String approvalProfileName = getApprovalProfileName();
        if (StringUtils.isNotEmpty(approvalProfileName)) {
            if (!StringTools.checkFieldForLegalChars(approvalProfileName)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                try {
                    approvalProfileSession.cloneApprovalProfile(getAdmin(), approvalProfileSession.getApprovalProfile(getSelectedApprovalProfileId()),
                            approvalProfileName);
                    setApprovalProfileName("");
                } catch (ApprovalProfileExistsException | ApprovalProfileDoesNotExistException | AuthorizationDeniedException e) {
                    addNonTranslatedErrorMessage(e.getLocalizedMessage());
                }

                actionCancel();
            }
        }
    }
    
    /** @return true if there exists an approval profile with the selected id */
    private boolean selectedProfileExists() {
        return getEjbcaWebBean().getEjb().getApprovalProfileSession().getApprovalProfile(selectedApprovalProfileId) != null;
    }

    public void actionAdd() {

        final String approvalProfileName = getApprovalProfileName();
        if (StringUtils.isNotEmpty(approvalProfileName)) {
            if (!StringTools.checkFieldForLegalChars(approvalProfileName)) {
                addErrorMessage("ONLYCHARACTERS");
            } else {
                try {
                    if (!approvalProfileSession.findByApprovalProfileName(approvalProfileName).isEmpty()) {
                        //Handle this below
                        throw new ApprovalProfileExistsException("Approval profile of name " + approvalProfileName + " already exists");
                    }
                    final ApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
                    approvalProfileSession.addApprovalProfile(getAdmin(), approvalProfile);
                    setApprovalProfileName("");
                } catch (ApprovalProfileExistsException e) {
                    addErrorMessage("APPROVAL_PROFILE_ALREADY_EXISTS");
                } catch (AuthorizationDeniedException e) {
                    addNonTranslatedErrorMessage("Not authorized to add approval profile.");
                }
            }
            approvalProfilesList = null;
        }
    }
    
}
