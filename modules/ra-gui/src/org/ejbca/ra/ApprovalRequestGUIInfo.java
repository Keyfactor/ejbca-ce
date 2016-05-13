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
import java.util.List;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalRequestInfo;

/**
 * Keeps localized information about an approval request.
 * 
 * @version $Id$
 */
public class ApprovalRequestGUIInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ApprovalRequestGUIInfo.class);
    
    public class StepOption {
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
    
    // This field is package-internal so RaManageRequest(s)Bean can use it internally. This class is specific to these beans.
    final RaApprovalRequestInfo request;
    
    private final String requestDate;
    private final String caName;
    private final String type;
    private final String displayName;
    private final String detail;
    private final String status;
    
    // Information about the current step (if any)
    private boolean hasNextStep;
    private int stepId;
    /** Type of step, corresponds to ApprovalStep.METADATATYPE_* constants*/
    private int stepType;
    private String stepText;
    private List<StepOption> stepOptions;
    
    // Whether the current admin can approve this request
    private boolean canApprove;
    
    public ApprovalRequestGUIInfo(final RaApprovalRequestInfo request, final RaLocaleBean raLocaleBean) {
        this.request = request;
        requestDate = ValidityDate.formatAsISO8601ServerTZ(request.getRequestDate().getTime(), TimeZone.getDefault());
        
        if (request.getCaId() == ApprovalDataVO.ANY_CA) {
            caName = raLocaleBean.getMessage("manage_requests_no_ca");
        } else if (request.getCaName() == null) {
            caName = "Missing CA id " + request.getCaId();
        } else {
            caName = request.getCaName();
        }
        
        switch (request.getType()) {
        case ApprovalDataVO.APPROVALTYPE_ADDENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_add_end_entity"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE: type = raLocaleBean.getMessage("manage_requests_type_revoke_certificate"); break;
        case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY: type = raLocaleBean.getMessage("manage_requests_type_revoke_end_entity"); break;
        default:
            log.info("Invalid/unsupported type of approval request: " + request.getType());
            type = "???";
        }
        
        /*username = request.getUsername();
        subjectDN = request.getSubjectDN();*/
        /*String cn = CertTools.getPartFromDN(subjectDN, "CN");
        if (cn == null) {
            cn = subjectDN;
        }*/
        displayName = "TODO"; // TODO could show CN or fall back to Subject DN for End Entity approval requests
        detail = "TODO"; // TODO could show full DN for End Entity approval requests
        
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
        
        //step = new ApprovalStepGUIInfo(stepId, indexInStep, type, nameText, options);
    }
    
    public String getId() { return String.valueOf(request.getId()); }
    public String getRequestDate() { return requestDate; }
    public boolean isHasCa() { return request.getCaId() != ApprovalDataVO.ANY_CA; }
    public String getCa() { return caName; }
    public String getType() { return type; }
    public String getDisplayName() { return displayName; }
    public String getDetail() { return detail; }
    public String getStatus() { return status; }
    
    public boolean isHasNextStep() { return hasNextStep && canApprove; }
    public String getStepText() { return stepText; }
    public boolean isCheckboxStep() { return isHasNextStep() && stepType == ApprovalStep.METADATATYPE_CHECKBOX; }
    public boolean isRadiobuttonStep() { return isHasNextStep() && stepType == ApprovalStep.METADATATYPE_RADIOBUTTON; }
    public boolean isTextboxStep() { return isHasNextStep() && stepType == ApprovalStep.METADATATYPE_TEXTBOX; }
    public List<StepOption> getStepOptions() { return stepOptions; }

    public boolean isCanApprove() { return canApprove; }
}
