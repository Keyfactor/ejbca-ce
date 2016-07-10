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

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.era.RaApprovalEditRequest;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaApprovalResponseRequest.Action;
import org.ejbca.core.model.era.RaEditableRequestData;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.ApprovalRequestGUIInfo.RequestDataRow;

/**
 * Backing bean for Manage Request page (for individual requests).
 *  
 * @see RaManageRequestsBean
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaManageRequestBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaManageRequestBean.class);
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    
    private ApprovalRequestGUIInfo requestInfo;
    private RaApprovalRequestInfo requestData;
    private boolean editing = false;
    
    private void loadRequest(final int id) {
        requestData = raMasterApiProxyBean.getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), id);
        if (requestData == null) {
            throw new IllegalStateException("Request does not exist, or user is not allowed to see it at this point");
        }
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean);
    }
    private void loadRequestByApprovalId(final int approvalId) {
        requestData = raMasterApiProxyBean.getApprovalRequestByRequestHash(raAuthenticationBean.getAuthenticationToken(), approvalId);
        if (requestData == null) {
            throw new IllegalStateException("Request does not exist, or user is not allowed to see it at this point");
        }
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean);
    }
    
    private void initializeRequestInfo() {
        if (requestInfo == null) {
            final String idHttpParam = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("id");
            if (idHttpParam!=null) {
                final int id = Integer.parseInt(idHttpParam);
                loadRequest(id);
            } else {
                final String aidHttpParam = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("aid");
                final int approvalId = Integer.parseInt(aidHttpParam);
                loadRequestByApprovalId(approvalId);
            }
        }
    }
    
    private void reloadRequest() {
        loadRequest(requestData.getId());
    }
    
    public ApprovalRequestGUIInfo getRequest() {
        initializeRequestInfo();
        return requestInfo;
    }
    
    public String getPageTitle() {
        return raLocaleBean.getMessage("view_request_page_title", getRequest().getDisplayName());
    }
    
    public boolean isViewDataVisible() { return !editing; }
    public boolean isEditDataVisible() { return editing; }
    public boolean isStatusVisible() { return !editing; }
    public boolean isPreviousStepsVisible() { return !editing && !requestInfo.getPreviousSteps().isEmpty(); }
    public boolean isApprovalVisible() { return !editing; }
    
    public boolean isHasNextStep() {
        initializeRequestInfo();
        return requestInfo != null && requestInfo.getNextStep() != null;
    }
    
    public List<ApprovalRequestGUIInfo.StepControl> getNextStepControls() {
        initializeRequestInfo();
        if (requestInfo != null && requestInfo.getNextStep() != null) {
            return getRequest().getNextStep().getControls();
        } else {
            return null;
        }
    }
    
    public String getCantApproveReason() {
        if (requestInfo.isExpired()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_expired");
        } else if (requestInfo.isPendingExecution()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_pending_execution");
        } else if (requestInfo.isExecuted()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_already_executed");
        } else if (requestInfo.isExecutionFailed()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_already_executed_failed");
        } else if (!requestInfo.isWaitingForApproval()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_not_waiting");
        } else if (requestInfo.isPending()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_pending");
        } else if (requestInfo.isEditedByMe()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_edited_by_me");
        } else {
            return raLocaleBean.getMessage("view_request_page_cannot_approve");
        }
    }
    
    private RaApprovalResponseRequest buildApprovalResponseRequest(final Action action) {
        final List<ApprovalRequestGUIInfo.StepControl> controls = getNextStepControls();
        final int id = getRequest().request.getId();
        
        final ApprovalStep step = getRequest().request.getNextApprovalStep();
        final int stepId = step.getStepIdentifier();
        final ApprovalPartition partition = getRequest().request.getRelevantApprovalPartition();
        final int partitionId = partition.getPartitionIdentifier();
        final RaApprovalResponseRequest approval = new RaApprovalResponseRequest(id, stepId, partitionId,  "", action); // TODO comment field. should it be here for partitioned approvals also?
        for (final ApprovalRequestGUIInfo.StepControl control : controls) {
            approval.addMetadata(control.getMetadataId(), control.getOptionValue(), control.getOptionNote());
        }
        return approval;
    }
    
    public void approve() throws AuthorizationDeniedException, AuthenticationFailedException {
        final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.APPROVE);
        try {
            if (raMasterApiProxyBean.addRequestResponse(raAuthenticationBean.getAuthenticationToken(), responseReq)) {
                raLocaleBean.addMessageInfo("view_request_page_success_approve");
            } else {
                raLocaleBean.addMessageError("generic_unexpected_no_backend");
            }
        } catch (ApprovalException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_generic");
            logException("approve", e);
        } catch (ApprovalRequestExpiredException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_expired");
            logException("approve", e);
        } catch (ApprovalRequestExecutionException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_execution");
            logException("approve", e);
        } catch (AdminAlreadyApprovedRequestException e) {
            raLocaleBean.addMessageError("view_request_page_error_already_approved");
            logException("approve", e);
        } catch (SelfApprovalException e) {
            raLocaleBean.addMessageError("view_request_page_error_self_approval");
            logException("approve", e);
        }
        
        reloadRequest();
    }
    
    public void reject() throws AuthorizationDeniedException, AuthenticationFailedException {
        final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.REJECT);
        try {
            if (raMasterApiProxyBean.addRequestResponse(raAuthenticationBean.getAuthenticationToken(), responseReq)) {
                raLocaleBean.addMessageInfo("view_request_page_success_reject");
            } else {
                raLocaleBean.addMessageError("generic_unexpected_no_backend");
            } 
        } catch (ApprovalException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_generic_reject");
            logException("reject", e);
        } catch (ApprovalRequestExpiredException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_expired");
            logException("reject", e);
        } catch (ApprovalRequestExecutionException e) {
            raLocaleBean.addMessageError("view_request_page_error_approval_execution");
            logException("reject", e);
        } catch (AdminAlreadyApprovedRequestException e) {
            raLocaleBean.addMessageError("view_request_page_error_already_approved");
            logException("reject", e);
        } catch (SelfApprovalException e) {
            raLocaleBean.addMessageError("view_request_page_error_self_approval");
            logException("reject", e);
        }
        
        reloadRequest();
    }
    
    public void editRequestData() {
        editing = true;
    }
    
    public void saveRequestData() throws AuthorizationDeniedException {
        if (!editing) {
            throw new IllegalStateException();
        }
        
        final RaEditableRequestData editData = requestData.getEditableData();
        for (final RequestDataRow dataRow : requestInfo.getRequestData()) {
            switch (dataRow.getKey()) {
            case "SUBJECTDN":
                editData.setSubjectDN(getDN(dataRow));
                break;
            case "SUBJECTALTNAME":
                editData.setSubjectAltName(getDN(dataRow));
                break;
            case "SUBJECTDIRATTRIBUTES":
                editData.setSubjectDirAttrs(getDN(dataRow));
                break;
            case "EMAIL":
                String email = (String) dataRow.getEditValue();
                // TODO validation
                editData.setEmail(email);
                break;
            }
        }
        
        // TODO error handling
        final RaApprovalEditRequest editReq = new RaApprovalEditRequest(requestData.getId(), editData);
        requestData = raMasterApiProxyBean.editApprovalRequest(raAuthenticationBean.getAuthenticationToken(), editReq);
        if (requestData == null) {
            throw new IllegalStateException("Request does not exist, or user is not allowed to see it at this point");
        }
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean);
        editing = false;
    }
    
    public String getDN(final RequestDataRow dataRow) {
        // TODO validation
        return (String) dataRow.getEditValue();
    }
    
    /** Logs the message of an exception, which usually contains some message. For example: "You may not approve an action which you requested yourself" */
    private void logException(final String action, final Throwable t) {
        if (log.isDebugEnabled()) {
            log.debug("Got exception while trying to " + action + " an approval request: " + t.getMessage());
        }
    }
    
}
