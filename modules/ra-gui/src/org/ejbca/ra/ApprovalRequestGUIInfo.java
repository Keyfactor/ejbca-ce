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

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaEditableRequestData;

/**
 * Keeps localized information about an approval request.
 * 
 * @version $Id$
 */
public class ApprovalRequestGUIInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ApprovalRequestGUIInfo.class);
    
    /**
     * A display POJO for approval partitions.
     */
    public class ApprovalPartitionProfileGuiObject {

        private List<DynamicUiProperty<? extends Serializable>> profilePropertyList = null;

        private final int partitionId;
        private final int stepId;

        public ApprovalPartitionProfileGuiObject(final int stepId, final int partitionId,
                List<DynamicUiProperty<? extends Serializable>> propertyValues) {
            //Pass property values as a parameter because it may need some outside poking
            setProfilePropertyList(propertyValues);
            this.stepId = stepId;
            this.partitionId = partitionId;
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
    
    public static final class Step implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int stepId;
        private final Integer stepOrdinal;
        private final String headingText;
        
        public Step(final ApprovalStep approvalStep, final RaApprovalRequestInfo request, final RaLocaleBean raLocaleBean) {
            stepId = approvalStep.getStepIdentifier();
            final Map<Integer,Integer> stepToOrdinal = request.getStepIdToOrdinalMap();
            stepOrdinal = stepToOrdinal.get(approvalStep.getStepIdentifier());
            headingText = raLocaleBean.getMessage("view_request_page_step", stepOrdinal, stepToOrdinal.size());
        }
        
        public int getStepId() {
            return stepId;
        }
        
        public int getStepOrdinal() {
            if(stepOrdinal==null) {
                return 0;
            }
            return stepOrdinal;
        }
        
        public String getHeadingText() {
            return headingText;
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
    
    private final String requestDate;
    private final String caName;
    private final String type;
    private final String requesterName;
    private final String displayName;
    private final String detail;
    private final String status;
    
    private final List<RequestDataRow> requestData;
    
    private final Step nextStep;
    private final List<Step> previousSteps;

    private final List<String> editLogEntries;
    
    // Whether the current admin can approve this request
    private boolean canApprove;
    private boolean canEdit;
    
    public ApprovalRequestGUIInfo(final RaApprovalRequestInfo request, final RaLocaleBean raLocaleBean) {
        this.request = request;
        if (request.getRequestData() != null) {
            requestData = new ArrayList<>();
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
                requestData.add(new RequestDataRow(raLocaleBean, dataText, editingSupported, editValue));
            }
        } else {
            requestData = null;
        }
        
        requestDate = ValidityDate.formatAsISO8601ServerTZ(request.getRequestDate().getTime(), TimeZone.getDefault());
        
        if (request.getCaId() == ApprovalDataVO.ANY_CA) {
            caName = raLocaleBean.getMessage("manage_requests_no_ca");
        } else if (request.getCaName() == null) {
            caName = "Missing CA id " + request.getCaId();
        } else {
            caName = request.getCaName();
        }
        
        final String reqSubjDN = request.getRequesterSubjectDN();
        if (reqSubjDN != null) {
            requesterName = getCNOrFallback(reqSubjDN, reqSubjDN);
        } else {
            requesterName = "";
        }
        
        switch (request.getType()) {
        case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_add_end_entity"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE: type = raLocaleBean.getMessage("manage_requests_type_revoke_certificate"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_revoke_end_entity"); break;
        default:
            log.info("Invalid/unsupported type of approval request: " + request.getType());
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
            nextStep = new Step(nextApprovalStep, request, raLocaleBean);
            canApprove = true;
        } else {
            nextStep = null;
            canApprove = false; // TODO can it be true in "number of approvals" mode?
        }
        canEdit = request.isEditable();
        
        previousSteps = new ArrayList<>();
        for (final ApprovalStep prevApprovalStep : request.getPreviousApprovalSteps()) {
            previousSteps.add(new Step(prevApprovalStep, request, raLocaleBean));
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
    public boolean isHasCa() { return request.getCaId() != ApprovalDataVO.ANY_CA; }
    public String getCa() { return caName; }
    public String getType() { return type; }
    public String getRequesterName() { return requesterName; }
    public String getDisplayName() { return displayName; }
    public String getDetail() { return detail; }
    public String getStatus() { return status; }
    
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
    
    public boolean isHasNextStep() { return nextStep != null && canApprove; }
    public Step getNextStep() { return nextStep; }
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
