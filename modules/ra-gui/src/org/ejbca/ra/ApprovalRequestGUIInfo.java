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
import java.util.TimeZone;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.approval.ApprovalStepMetadata;
import org.ejbca.core.model.era.RaApprovalRequestInfo;

/**
 * Keeps localized information about an approval request.
 * 
 * @version $Id$
 */
public class ApprovalRequestGUIInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ApprovalRequestGUIInfo.class);
    
    public static class StepOption implements Serializable {
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
    
    public static class StepControl implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int id;
        /** Type of control, corresponds to ApprovalStep.METADATATYPE_* constants*/
        private final int optionsType;
        private final String instruction;
        private final String[] options;
        private String optionNote;
        private String optionValue;
        
        public StepControl(final ApprovalStepMetadata metadata) {
            id = metadata.getMetadataId();
            instruction = metadata.getInstruction();
            optionsType = metadata.getOptionsType();
            final List<String> optionsList = metadata.getOptions();
            options = optionsList.toArray(new String[optionsList.size()]);
            optionNote = metadata.getOptionNote();
        }
        
        public String getInstruction() { return instruction; }
        public boolean isCheckbox() { return optionsType == ApprovalStepMetadata.METADATATYPE_CHECKBOX; }
        public boolean isRadiobutton() { return optionsType == ApprovalStepMetadata.METADATATYPE_RADIOBUTTON; }
        public boolean isTextbox() { return optionsType == ApprovalStepMetadata.METADATATYPE_TEXTBOX; }
        
        public String[] getOptions() { return options; }
        public String getRadiobuttonValue() { return optionValue; }
        public void setRadiobuttonValue(final String rbvalue) { optionValue = rbvalue; }
        public String[] getCheckboxValue() { return (optionValue != null ? optionValue.split("; *") : ArrayUtils.EMPTY_STRING_ARRAY); }
        public void setCheckboxValue(final String[] cbvalue) { optionValue = StringUtils.join(cbvalue, "; "); }
        public String getTextValue() { return optionValue; }
        public void setTextValue(final String textValue) { optionValue = textValue; }
        
        public String getOptionNote() { return optionNote; }
        public void setOptionNote(final String optionNote) { this.optionNote = optionNote; }
    }
    
    public static class Step implements Serializable {
        private static final long serialVersionUID = 1L;
        private final int stepId;
        private final List<StepControl> controls;
        
        public Step(final ApprovalStep approvalStep) {
            controls = new ArrayList<>();
            for (final ApprovalStepMetadata metadata : approvalStep.getMetadata()) {
                controls.add(new StepControl(metadata));
            }
            stepId = approvalStep.getStepId();
        }
        
        public List<StepControl> getControls() {
            return controls;
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
    
    private final Step nextStep;
    private final List<Step> previousSteps;
    
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
        
        final ApprovalStep nextApprovalStep = request.getNextApprovalStep();
        if (nextApprovalStep != null) {
            nextStep = new Step(nextApprovalStep);
            canApprove = true;
        } else {
            nextStep = null;
            canApprove = false; // TODO can it be true in "number of approvals" mode?
        }
        
        previousSteps = new ArrayList<>();
        // TODO previous steps
    }
    
    public String getId() { return String.valueOf(request.getId()); }
    public String getRequestDate() { return requestDate; }
    public boolean isHasCa() { return request.getCaId() != ApprovalDataVO.ANY_CA; }
    public String getCa() { return caName; }
    public String getType() { return type; }
    public String getDisplayName() { return displayName; }
    public String getDetail() { return detail; }
    public String getStatus() { return status; }

    public boolean isHasNextStep() { return nextStep != null && canApprove; }
    public Step getNextStep() { return nextStep; }
    public boolean isCanApprove() { return canApprove; }
    
}
