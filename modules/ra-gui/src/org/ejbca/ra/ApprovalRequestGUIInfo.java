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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalStepInfo;
import org.ejbca.core.model.era.RaEditableRequestData;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Keeps localized information about an approval request.
 * 
 * @version $Id$
 */
public class ApprovalRequestGUIInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ApprovalRequestGUIInfo.class);
    
    public static final class ApprovalGuiObject {
        private Approval approval;
        
        public ApprovalGuiObject(Approval approval) {
           this.approval = approval;
        }
        
        public String getApprovalDate(){
            return ValidityDate.formatAsISO8601(approval.getApprovalDate(), ValidityDate.TIMEZONE_SERVER);
        }
        public String getApprovalAdmin(){
            return approval.getAdmin().toString();
        }
        
        public String getAdminAction(){
            if(approval.isApproved()){
                return "APPROVED";
            }
            return "REJECTED";
        }
        public String getComment(){
            return approval.getComment();
        }
    }
    
    /**
     * A display POJO for approval partitions.
     */
    public static final class ApprovalPartitionProfileGuiObject implements Serializable {
        private static final long serialVersionUID = 1L;

        private List<DynamicUiProperty<? extends Serializable>> profilePropertyList = null;

        private final int partitionId;
        private final int stepId;
        private final List<Approval> approvals;

        public ApprovalPartitionProfileGuiObject(final int stepId, final int partitionId,
                List<DynamicUiProperty<? extends Serializable>> propertyValues, List<Approval> approvals) {
            //Pass property values as a parameter because it may need some outside poking
            setProfilePropertyList(propertyValues);
            this.stepId = stepId;
            this.partitionId = partitionId;
            this.approvals = approvals;
        }

        public List<DynamicUiProperty<? extends Serializable>> getProfilePropertyList() {
            return profilePropertyList;
        }
        
        public void setProfilePropertyList(List<DynamicUiProperty<? extends Serializable>> profilePropertyList) {
            this.profilePropertyList = profilePropertyList;
        }

        public int getPartitionId() {
            return partitionId;
        }
        public int getStepId() {
            return stepId;
        }
        
        /** @return the current multi-valued property's possible values as JSF friendly SelectItems. */
        public List<SelectItem/*<String,String>*/> getPropertyPossibleValues( final DynamicUiProperty<? extends Serializable> property) {
            final List<SelectItem> propertyPossibleValues = new ArrayList<SelectItem>();
            if (profilePropertyList != null) {
                if (property != null && property.getPossibleValues() != null) {
                    for (final Serializable possibleValue : property.getPossibleValues()) {
                        propertyPossibleValues
                                .add(new SelectItem(property.getAsEncodedValue(property.getType().cast(possibleValue)), possibleValue.toString()));
                    }
                }
            }
            return propertyPossibleValues;
        }
        
        public List<Approval> getApprovals() {
            return this.approvals;
        }
        
    }
    
    public static final class StepOption implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String name;
        private Object value;
        
        public StepOption(final String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
        
        public Object getValue() {
            return value;
        }

        public void setValue(final Object value) {
            this.value = value;
        }
    }
    
    /** Represents a step that has been approved */
    public static final class Step implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int stepId;
        private final Integer stepOrdinal;
        private final String headingText;
        private final List<ApprovalPartition> partitions;
        
        public Step(final RaApprovalStepInfo stepInfo, final RaApprovalRequestInfo request, final RaLocaleBean raLocaleBean) {
            stepId = stepInfo.getStepId();
            final Map<Integer,Integer> stepToOrdinal = request.getStepIdToOrdinalMap();
            stepOrdinal = stepToOrdinal.get(stepId);
            headingText = raLocaleBean.getMessage("view_request_page_step", stepOrdinal);
            partitions = stepInfo.getPartitions();
        }
        
        public int getStepId() {
            return stepId;
        }
        
        public int getStepOrdinal() {
            if (stepOrdinal==null) {
                return 0;
            }
            return stepOrdinal;
        }
        
        public String getHeadingText() {
            return headingText;
        }
        
        public List<ApprovalPartition> getPartitions() {
            return partitions;
        }
    }
    
    public static final class RequestDataRow implements Serializable {
        private static final long serialVersionUID = 1L;
        private final ApprovalDataText approvalDataText;
        private final RaLocaleBean raLocaleBean;
        private final boolean editingSupported;
        private Object editValue; // TODO the column maps to a translation id. does it also map to something in the *ApprovalRequest data hashmap?
        
        
        public RequestDataRow(final RaLocaleBean raLocaleBean, final ApprovalDataText approvalDataText, final boolean editingSupported, final Object editValue) {
            this.approvalDataText = approvalDataText;
            this.raLocaleBean = raLocaleBean;
            this.editingSupported = editingSupported;
            this.editValue = editValue;
        }
        
        public String getKey() {
            return approvalDataText.getHeader();
        }
        
        public String getHeader() {
            if (approvalDataText.isHeaderTranslateable()) {
                return raLocaleBean.getMessage("view_request_page_data_header_" + approvalDataText.getHeader());
            } else {
                return approvalDataText.getHeader();
            }
        }
        
        public String getData() {
            if (approvalDataText.isDataTranslatable()) {
                return raLocaleBean.getMessage("view_request_page_data_value_" + approvalDataText.getData());
            } else {
                return approvalDataText.getData();
            }
        }
        
        public boolean isEditingSupported() {
            return editingSupported;
        }
        
        public Object getEditValue() {
            return editValue;
        }
        
        public void setEditValue(final Object editValue) {
            this.editValue = editValue;
        }
    }
    
    // This field is package-internal so RaManageRequest(s)Bean can use it internally. This class is specific to these beans.
    final RaApprovalRequestInfo request;
    private final ApprovalDataVO approvalData;
    
    private final String requestDate;
    private final String caName;
    private final String type;
    private final String requesterName;
    private final String displayName;
    private final String detail;
    private final String status;
    
    private final RaEndEntityDetails endEntityDetails;
    private final List<RequestDataRow> requestData;
    
    private final List<Step> previousSteps;

    private final List<String> editLogEntries;
    
    // Whether the current admin can approve this request
    private boolean canApprove;
    private boolean canEdit;
    
    public ApprovalRequestGUIInfo(final RaApprovalRequestInfo request, final RaLocaleBean raLocaleBean) {
        this.request = request;
        approvalData = request.getApprovalData();
        
        // Determine what parts of the approval request are editable
        final EndEntityInformation endEntityInformation = getEndEntityInformation(); // editable
        boolean hasEditableData = (endEntityInformation != null);
        requestData = new ArrayList<>();
        if (request.getRequestData() != null && endEntityInformation == null) {
            final RaEditableRequestData editData  = request.getEditableData();
            for (final ApprovalDataText dataText : request.getRequestData()) {
                boolean editingSupported = true;
                final Object editValue;
                switch (dataText.getHeader()) {
                case "SUBJECTDN":
                    editValue = editData.getSubjectDN();
                    break;
                case "SUBJECTALTNAME":
                    editValue = editData.getSubjectAltName();
                    break;
                case "SUBJECTDIRATTRIBUTES":
                    if ("NOVALUE".equals(dataText.getData())) continue;
                    editValue = editData.getSubjectDirAttrs();
                    break;
                case "EMAIL":
                    editValue = editData.getEmail();
                    break;
                // Suppress some "no" or "none" values
                case "HARDTOKENISSUERALIAS":
                case "KEYRECOVERABLE":
                case "SENDNOTIFICATION":
                    if ("NOVALUE".equals(dataText.getData()) || "NO".equals(dataText.getData())) continue;
                    // NOPMD: Fall through
                default:
                    editingSupported = false;
                    editValue = null;
                }
                if (editingSupported) {
                    hasEditableData = true;
                }
                requestData.add(new RequestDataRow(raLocaleBean, dataText, editingSupported, editValue));
            }
        }
        
        requestDate = ValidityDate.formatAsISO8601ServerTZ(approvalData.getRequestDate().getTime(), TimeZone.getDefault());
        requestData.add(new RequestDataRow(raLocaleBean, new ApprovalDataText("REQUESTDATE", getRequestDate(), true, false), false, null));
        
        if (approvalData.getCAId() == ApprovalDataVO.ANY_CA) {
            caName = raLocaleBean.getMessage("manage_requests_no_ca");
        } else if (request.getCaName() == null) {
            caName = "Missing CA id " + approvalData.getCAId();
        } else {
            caName = request.getCaName();
        }
        
        if (endEntityInformation != null) {
            final EndEntityProfile endEntityProfile = request.getEndEntityProfile();
            final RaEndEntityDetails.Callbacks callbacks = new RaEndEntityDetails.Callbacks() {
                @Override
                public RaLocaleBean getRaLocaleBean() { return raLocaleBean; }
                @Override
                public EndEntityProfile getEndEntityProfile(int eepId) { return endEntityProfile; }
            };
            endEntityDetails = new RaEndEntityDetails(getEndEntityInformation(), callbacks, request.getCertificateProfileName(), request.getEndEntityProfileName(), caName);
        } else {
            endEntityDetails = null;
        }
        
        final String reqSubjDN = request.getRequesterSubjectDN();
        if (reqSubjDN != null) {
            requesterName = getCNOrFallback(reqSubjDN, reqSubjDN);
        } else {
            requesterName = "";
        }
        
        switch (approvalData.getApprovalType()) {
        case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_add_end_entity"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE: type = raLocaleBean.getMessage("manage_requests_type_revoke_certificate"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_revoke_end_entity"); break;
        default:
            log.info("Invalid/unsupported type of approval request: " + approvalData.getApprovalType());
            type = "???";
        }
        
        // These are currently unavailable in the listing page for performance reasons
        final String username = getRequestData("USERNAME");
        final String subjectDN = getRequestData("SUBJECTDN");
        displayName = getCNOrFallback(subjectDN, username);
        detail = subjectDN;
        
        switch (request.getStatus()) {
        case ApprovalDataVO.STATUS_APPROVED: status = raLocaleBean.getMessage("manage_requests_status_approved"); break;
        case ApprovalDataVO.STATUS_EXECUTED: status = raLocaleBean.getMessage("manage_requests_status_executed"); break;
        case ApprovalDataVO.STATUS_EXECUTIONDENIED: status = raLocaleBean.getMessage("manage_requests_status_execution_denied"); break;
        case ApprovalDataVO.STATUS_EXECUTIONFAILED: status = raLocaleBean.getMessage("manage_requests_status_execution_failed"); break;
        case ApprovalDataVO.STATUS_EXPIRED: status = raLocaleBean.getMessage("manage_requests_status_expired"); break;
        case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED: status = raLocaleBean.getMessage("manage_requests_status_expired_and_notified"); break;
        case ApprovalDataVO.STATUS_REJECTED: status = raLocaleBean.getMessage("manage_requests_status_rejected"); break;
        case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL: status = raLocaleBean.getMessage("manage_requests_status_waiting_for_approval"); break;
        default:
            log.info("Invalid status of approval request: " + request.getStatus());
            status = "???";
        }
        
        editLogEntries = new ArrayList<>();
        for (final TimeAndAdmin entry : request.getEditedByAdmin()) {
            final String editDate = ValidityDate.formatAsISO8601(entry.getDate(), TimeZone.getDefault());
            final String adminName;
            if (entry.getAdmin() instanceof X509CertificateAuthenticationToken) {
                final String adminDN = CertTools.getSubjectDN(((X509CertificateAuthenticationToken)entry.getAdmin()).getCertificate());
                adminName = getCNOrFallback(adminDN, adminDN);
            } else {
                adminName = entry.getAdmin().toString();
            }
            editLogEntries.add(raLocaleBean.getMessage("view_request_page_edit_log_entry", editDate, adminName));
        }
        
        // Steps
        final ApprovalStep nextApprovalStep = request.getNextApprovalStep();
        if (nextApprovalStep != null && !request.isEditedByMe() && !request.isApprovedByMe() && !request.isRequestedByMe()) {
            canApprove = true;
        } else {
            canApprove = false; // TODO can it be true in "number of approvals" mode?
        }
        canEdit = request.isEditable() && hasEditableData;
        
        previousSteps = new ArrayList<>();
        for (final RaApprovalStepInfo stepInfo : request.getPreviousApprovalSteps()) {
            previousSteps.add(new Step(stepInfo, request, raLocaleBean));
        }
        
    }
    
    private String getCNOrFallback(final String subjectDN, final String fallback) {
        final String cn = CertTools.getPartFromDN(subjectDN, "CN");
        if (cn != null) {
            return cn;
        } else if (fallback != null) {
            return fallback;
        } else {
            return "";
        }
    }
    
    public String getId() { return String.valueOf(request.getId()); }
    public String getRequestDate() { return requestDate; }
    public String getCa() { return caName; }
    public String getType() { return type; }
    public String getRequesterName() { return requesterName; }
    public String getDisplayName() { return displayName; }
    public String getDetail() { return detail; }
    public String getStatus() { return status; }
    
    public EndEntityInformation getEndEntityInformation() {
        final ApprovalRequest approvalRequest = request.getApprovalRequest();
        if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            return ((AddEndEntityApprovalRequest)approvalRequest).getEndEntityInformation();
        } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            return ((EditEndEntityApprovalRequest)approvalRequest).getNewEndEntityInformation();
        } else {
            return null;
        }
    }
    public RaEndEntityDetails getEndEntityDetails() { return endEntityDetails; }
    
    public List<RequestDataRow> getRequestData() { return requestData; }
    private String getRequestData(final String key) {
        if (requestData != null) {
            for (final RequestDataRow row : requestData) {
                if (row.getKey().equals(key)) {
                    return row.getData();
                }
            }
        }
        return null;
    }

    public List<String> getEditLogEntries() { return editLogEntries; }
    
    public List<Step> getPreviousSteps() { return previousSteps; }
    public int getStepCount() { return request.getStepCount(); }
    public int getCurrentStepOrdinal() { return request.getCurrentStepOrdinal(); }
    
    public boolean isCanApprove() { return canApprove; }
    public boolean isCanEdit() { return canEdit; }
    public boolean isEditedByMe() { return request.isEditedByMe(); }
    public boolean isPending() { return request.isPending(); }
    public boolean isPendingExecution() { return request.getStatus() == ApprovalDataVO.STATUS_APPROVED; /* = approved but not executed */ }
    public boolean isExecuted() { return request.getStatus() == ApprovalDataVO.STATUS_EXECUTED; }
    public boolean isSuccessful() { return isExecuted() || isPendingExecution(); }
    public boolean isUnsuccessful() { return !isWaitingForApproval() && !isSuccessful(); }
    public boolean isExecutionFailed() { return request.getStatus() == ApprovalDataVO.STATUS_EXECUTIONFAILED; }
    public boolean isWaitingForMe() { return request.isWaitingForMe(); }
    public boolean isWaitingForApproval() { return request.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL; }
    public boolean isExpired() { return request.getStatus() == ApprovalDataVO.STATUS_EXPIRED || request.getStatus() == ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED; }
    
}
