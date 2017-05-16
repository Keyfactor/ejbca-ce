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
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.ejbca.core.model.era.RaApprovalEditRequest;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaApprovalResponseRequest.Action;
import org.ejbca.core.model.era.RaEditableRequestData;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.ApprovalRequestGUIInfo.RequestDataRow;
import org.ejbca.util.KeyValuePair;

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

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }
    
    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }
    
    private ApprovalRequestGUIInfo requestInfo;
    private RaApprovalRequestInfo requestData;
    private boolean editing = false;
    private String extendDays;
    private Map<Integer, List<DynamicUiProperty<? extends Serializable>> > currentPartitionsProperties = null;
    List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> partitionsAuthorizedToView = null;
    Set<Integer> partitionsAuthorizedToApprove = null;
    
    public String idParam;
    public String aidParam;
    
    public String getIdParam() { return idParam; }
    public void setIdParam(final String value) { idParam = value; }
    public String getAidParam() { return aidParam; }
    public void setAidParam(final String value) { aidParam = value; }
    
    private void loadRequest(final int id) {
        requestData = raMasterApiProxyBean.getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), id);
        if (requestData == null) {
            throw new IllegalStateException("Request does not exist, or user is not allowed to see it at this point");
        }
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean, raAccessBean);
    }
    private void loadRequestByApprovalId(final int approvalId) {
        requestData = raMasterApiProxyBean.getApprovalRequestByRequestHash(raAuthenticationBean.getAuthenticationToken(), approvalId);
        if (requestData == null) {
            throw new IllegalStateException("Request does not exist, or user is not allowed to see it at this point");
        }
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean, raAccessBean);
    }
    
    public void initializeRequestInfo() {
        if (requestInfo == null) {
            if (!StringUtils.isBlank(idParam)) {
                final int id = Integer.parseInt(idParam);
                loadRequest(id);
            } else if (!StringUtils.isBlank(aidParam)) {
                final int approvalId = Integer.parseInt(aidParam);
                loadRequestByApprovalId(approvalId);
            } else {
                // JBoss EAP 6 can call this method from preRenderView event, even from the listing page. In that case there's no ID parameter.    
                log.debug("No request ID passed in parameter. Will not initialize request info.");
                return;
            }
            if (requestData.getApprovalProfile() != null) {
                long defaultExtensionMillis = Math.min(requestData.getApprovalProfile().getApprovalExpirationPeriod(),
                        requestData.getMaxExtensionTime());
                extendDays = String.valueOf((defaultExtensionMillis + 24*60*60*1000 - 1) / (24*60*60*1000));
            } else {
                extendDays = "1";
            }
        }
    }
    
    private void reloadRequest() {
        loadRequest(requestData.getId());
        // Make sure we don't use the approvalId (the hash) after we have edited a request
        idParam = String.valueOf(requestData.getId());
        aidParam = null;
    }
    
    public ApprovalRequestGUIInfo getRequest() {
        return requestInfo;
    }
    
    public String getPageTitle() {
        return raLocaleBean.getMessage("view_request_page_title", requestInfo.getDisplayName());
    }
    
    public boolean isViewDataVisible() { return !editing; }
    public boolean isEditDataVisible() { return editing; }
    public boolean isStatusVisible() { return !editing; }
    public boolean isPreviousStepsVisible() { return !editing && !requestInfo.getPreviousSteps().isEmpty(); }
    public boolean isApprovalVisible() { return !editing; } // even if approval is not possible, we still show a message explaining why it's not.
    
    public String getExtendDays() { return extendDays; }
    public void setExtendDays(final String extendDays) { this.extendDays = extendDays; }
    
    public String getPartitionName(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition) {
        if (guiPartition == null) {
            // JBoss EAP 6.4 seems to make calls EL method calls one time extra, with a null parameter, once per page rendering
            log.debug("Ignored call to getPartitionProperties with null parameter");
            return "";
        }
        final ApprovalProfile approvalProfile = requestInfo.request.getApprovalProfile();
        final ApprovalStep step = approvalProfile.getStep(guiPartition.getStepId());
        final ApprovalPartition partition = step.getPartition(guiPartition.getPartitionId());
        DynamicUiProperty<? extends Serializable> property = partition.getProperty(PartitionedApprovalProfile.PROPERTY_NAME);
        if (property != null) {
            return (String) property.getValue();
        }
        return "";
    }
    
    public List<DynamicUiProperty<? extends Serializable>> getPartitionProperties(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition) {
        if (guiPartition == null) {
            // JBoss EAP 6.4 seems to make calls EL method calls one time extra, with a null parameter, once per page rendering
            log.debug("Ignored call to getPartitionProperties with null parameter");
            return new ArrayList<>();
        }
        final ApprovalProfile approvalProfile = requestInfo.request.getApprovalProfile();
        final ApprovalStep step = approvalProfile.getStep(guiPartition.getStepId());
        final ApprovalPartition partition = step.getPartition(guiPartition.getPartitionId());
        return getPartitionProperties(approvalProfile, partition);
    }
    
    /** Returns partitions in the current step */
    public List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> getPartitions() {
        if (partitionsAuthorizedToView == null) {
            List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> authorizedPartitions = new ArrayList<>();
            partitionsAuthorizedToApprove = new HashSet<>();
            final ApprovalStep step = requestInfo.request.getNextApprovalStep();
            final ApprovalProfile approvalProfile = requestInfo.request.getApprovalProfile();
            if (step != null) {
                for (ApprovalPartition approvalPartition : step.getPartitions().values()) {
                    try {
                        if (approvalProfile.canViewPartition(raAuthenticationBean.getAuthenticationToken(), approvalPartition)) {
                            ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partitionGuiObject = 
                                    new ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject(step.getStepIdentifier(),
                                    approvalPartition.getPartitionIdentifier(), getPartitionProperties(approvalProfile, approvalPartition), 
                                    getPartitionApproval(approvalPartition.getPartitionIdentifier(), step.getStepIdentifier()));
                            authorizedPartitions.add(partitionGuiObject);
                        }
                        if (approvalProfile.canApprovePartition(raAuthenticationBean.getAuthenticationToken(), approvalPartition)) {
                            partitionsAuthorizedToApprove.add(approvalPartition.getPartitionIdentifier());
                        }
                    } catch (AuthenticationFailedException e) {
                        //We shouldn't have gotten here in the UI with an invalid token
                        throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token: " + raAuthenticationBean.getAuthenticationToken(), e);
                    }
                }
            }
            partitionsAuthorizedToView = new ArrayList<>(authorizedPartitions);

        }
        return partitionsAuthorizedToView;
        
    }

    private List<Approval> getPartitionApproval(final int partitionId, final int stepId) {
        final ApprovalDataVO advo = requestInfo.request.getApprovalData();
        Collection<Approval> approvals = advo.getApprovals();
        List<Approval> partitionApprovals = new ArrayList<>();
        for(Approval approval : approvals) {
            if((approval.getStepId()==stepId) && (approval.getPartitionId()==partitionId)) {
                partitionApprovals.add(approval);
            }
        }
        return partitionApprovals;
    }
     
    /** 
     * @return true if there already exists an approval for this partition 
     */
    public boolean isPartitionHandled(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partition) {
        return getPartitionApproval(partition.getPartitionId(), partition.getStepId()).size() > 0;
    }
    public boolean canApproveParition(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partition) {
        if (partitionsAuthorizedToApprove == null) {
            getPartitions();
        }
        return partitionsAuthorizedToApprove.contains(partition.getPartitionId());
    }
    public boolean isPropertyReadOnly(String propertyName) {
        return requestInfo.request.getApprovalProfile().getReadOnlyProperties().contains(propertyName);
    }
    /** @return true if subject DN override by CSR is allowed */
    public boolean isDnOverride() {
        CertificateProfile certificateProfile = raMasterApiProxyBean.getCertificateProfile(requestInfo.getEndEntityInformation().getCertificateProfileId());
        return certificateProfile.getAllowDNOverride();
    }
    
    /**
     * Extract the partition properties, and fill in all and any placeholders. Also cull any properties set to be hidden.
     * 
     * @return a list of dynamic properties 
     */
    private List<DynamicUiProperty<? extends Serializable>> getPartitionProperties(final ApprovalProfile approvalProfile, ApprovalPartition approvalPartition) {
        if (currentPartitionsProperties == null || !currentPartitionsProperties.containsKey(approvalPartition.getPartitionIdentifier())) {
            Set<String> hiddenPropertyNames = approvalProfile.getHiddenProperties();    
            List<DynamicUiProperty<? extends Serializable>> propertyList = new ArrayList<>();
            for (String propertyName : approvalPartition.getPropertyList().keySet()) {
                if (!hiddenPropertyNames.contains(propertyName)) {
                    DynamicUiProperty<? extends Serializable> propertyClone = new DynamicUiProperty<>(
                            approvalPartition.getPropertyList().get(propertyName));
                    propertyList.add(propertyClone);
                }
            }
            
            if (currentPartitionsProperties == null) {
                currentPartitionsProperties = new HashMap<>();
            }
            currentPartitionsProperties.put(approvalPartition.getPartitionIdentifier(), propertyList);
        }
        return currentPartitionsProperties.get(approvalPartition.getPartitionIdentifier());
    }
    
    /** Creates a list of partitions that can be used with the approvalmetadata component */
    public List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> partitionsToGuiPartitions(final ApprovalRequestGUIInfo.Step step, final Iterable<ApprovalPartition> partitions) {
        if (partitions == null) {
            // JBoss EAP 6.4 seems to make calls EL method calls one time extra, with a null parameter, once per page rendering
            log.debug("Ignored call to partitionsToGuiPartitions with null parameter");
            return new ArrayList<>();
        }
        final List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> ret = new ArrayList<>();
        for (final ApprovalPartition partition : partitions) {
            ret.add(new ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject(step.getStepId(),
                    partition.getPartitionIdentifier(), getPartitionProperties(requestData.getApprovalProfile(), partition), 
                    getPartitionApproval(partition.getPartitionIdentifier(), step.getStepId())));
        }
        return ret;
    }
    
    public List<KeyValuePair> getHandledPartitionData(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition) {
        if (guiPartition == null) {
            // JBoss EAP 6.4 seems to make calls EL method calls one time extra, with a null parameter, once per page rendering
            log.debug("Ignored call to partitionsToGuiPartitions with null parameter");
            return new ArrayList<>();
        }
        
        ArrayList<KeyValuePair> kvp = new ArrayList<>();
        
        List<DynamicUiProperty<? extends Serializable>> properties = getPartitionProperties(guiPartition);
        for (DynamicUiProperty<? extends Serializable> property : properties) {
            kvp.add(new KeyValuePair(property.getName(), property.getValueAsString()));
        }
        List<Approval> approvals = getPartitionApproval(guiPartition.getPartitionId(), guiPartition.getStepId());
        for (Approval approval : approvals) {
            ApprovalRequestGUIInfo.ApprovalGuiObject approvalView = new ApprovalRequestGUIInfo.ApprovalGuiObject(approval);
            kvp.add(new KeyValuePair("Approval action", approvalView.getAdminAction()));
            kvp.add(new KeyValuePair("Approval date", approvalView.getApprovalDate()));
            kvp.add(new KeyValuePair("Approval administrator", approvalView.getApprovalAdmin()));
            kvp.add(new KeyValuePair("Approval comment", approvalView.getComment()));
        }
        return kvp;
    }   
    
    public String getStepInfoText() {
        final List<String> roles = new ArrayList<>(requestData.getNextStepAllowedRoles());
        if (!roles.isEmpty()) {
            Collections.sort(roles);
            return raLocaleBean.getMessage("view_request_page_step_of_with_roles", requestInfo.getCurrentStepOrdinal(), requestInfo.getStepCount(), StringUtils.join(roles, ", "));
        } else {
            return raLocaleBean.getMessage("view_request_page_step_of", requestInfo.getCurrentStepOrdinal(), requestInfo.getStepCount());
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
        } else if (!requestInfo.isAuthorizedToApprovalType()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_not_authorized");
        } else if (requestInfo.isEditedByMe()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_edited_by_me");
        } else if (requestInfo.isApprovedByMe()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_approved_by_me");
        } else if (requestInfo.isRequestedByMe()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_requested_by_me");  
        } else if (requestInfo.isPending(raAuthenticationBean.getAuthenticationToken())) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_pending");
        } else if (!requestInfo.hasNextApprovalStep()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_no_next_step");
        } else {
            return raLocaleBean.getMessage("view_request_page_cannot_approve");
        }
    }
    
    
    private RaApprovalResponseRequest buildApprovalResponseRequest(final Action action, ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiParition, 
                ApprovalProfile storedApprovalProfile, ApprovalDataVO advo) {
        ApprovalStep step = storedApprovalProfile.getStep(guiParition.getStepId());
        ApprovalPartition partition = step.getPartition(guiParition.getPartitionId());
        
        List<DynamicUiProperty<? extends Serializable>> updatedProperties =  getPartitionProperties(storedApprovalProfile, partition);
        storedApprovalProfile.addPropertiesToPartition(step.getStepIdentifier(), partition.getPartitionIdentifier(), updatedProperties);
        
        ApprovalRequest request = advo.getApprovalRequest();
        request.setApprovalProfile(storedApprovalProfile);

        final int id = requestInfo.request.getId();
        final int stepId = step.getStepIdentifier();
        final int partitionId = partition.getPartitionIdentifier();
        final RaApprovalResponseRequest approval = new RaApprovalResponseRequest(id, stepId, partitionId, request, "", action); // TODO comment field. should it be here for partitioned approvals also?
        return approval;
    }
    
    public void approve() throws AuthorizationDeniedException, AuthenticationFailedException {
        final ApprovalDataVO advo = requestInfo.request.getApprovalData();
        final ApprovalProfile approvalProfile = advo.getApprovalRequest().getApprovalProfile();
        
        for (ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition : partitionsAuthorizedToView) {
            if (partitionsAuthorizedToApprove.contains(guiPartition.getPartitionId())) {
                final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.APPROVE, guiPartition, approvalProfile, advo);
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
            }
        }

        reloadRequest();
    }
    
    public void reject() throws AuthorizationDeniedException, AuthenticationFailedException {
        final ApprovalDataVO advo = requestInfo.request.getApprovalData();
        final ApprovalProfile approvalProfile = advo.getApprovalRequest().getApprovalProfile();
        
        for (ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition : partitionsAuthorizedToView) {
            if (partitionsAuthorizedToApprove.contains(guiPartition.getPartitionId())) {
                final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.REJECT, guiPartition, approvalProfile, advo);
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
            }
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
        final RaEndEntityDetails endEntityDetails = requestInfo.getEndEntityDetails();
        if (endEntityDetails != null) {
            final SubjectDn sdn = endEntityDetails.getSubjectDistinguishedName();
            sdn.update();
            editData.setSubjectDN(sdn.getValue());
            
            final SubjectAlternativeName san = endEntityDetails.getSubjectAlternativeName();
            san.update();
            editData.setSubjectAltName(san.getValue());
            
            final SubjectDirectoryAttributes sda = endEntityDetails.getSubjectDirectoryAttributes();
            sda.update();
            editData.setSubjectDirAttrs(sda.getValue());
            
            editData.setEmail(endEntityDetails.getEmail());
        } else {
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
                    // TODO validation (ECA-5235)
                    editData.setEmail(email);
                    break;
                }
            }
            
            // Check that the end entity profile is fulfilled
            // TODO: ECA-5235
        }
        
        // TODO error handling
        final RaApprovalEditRequest editReq = new RaApprovalEditRequest(requestData.getId(), editData);
        final RaApprovalRequestInfo newReqData = raMasterApiProxyBean.editApprovalRequest(raAuthenticationBean.getAuthenticationToken(), editReq);
        if (newReqData == null) {
            raLocaleBean.addMessageError("view_request_page_error_edit");
            return;
        }
        requestData = newReqData;
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean, raAccessBean);
        editing = false;
    }
    
    public void cancelEdit() {
        if (!editing) {
            throw new IllegalStateException();
        }
        // Restore everything
        requestData = raMasterApiProxyBean.getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), requestData.getId());
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean, raAccessBean);
        editing = false;
    }
    
    public String extendRequest() throws AuthorizationDeniedException {
        if (StringUtils.isBlank(extendDays)) {
            raLocaleBean.addMessageError("view_request_page_error_extend_missing_days");
            return "";
        }
        
        final long extendForMillis = Long.valueOf(extendDays.trim()) * 24*60*60*1000;
        final long maxExtensionTime = requestInfo.request.getMaxExtensionTime();
        if (extendForMillis > maxExtensionTime) {
            raLocaleBean.addMessageError("view_request_page_error_extend_too_long", getMaxExtensionDays());
            return "";
        }
        raMasterApiProxyBean.extendApprovalRequest(raAuthenticationBean.getAuthenticationToken(), requestData.getId(), extendForMillis);
        return "managerequest.xhtml?faces-redirect=true&includeViewParams=true";
    }
    
    public int getMaxExtensionDays() {
        long days = requestInfo.request.getMaxExtensionTime() / (24*60*60*1000);
        return (int) days;
    }
    
    public String getExtendDaysPart2Text() {
        return raLocaleBean.getMessage("view_request_page_extend_days_2", getMaxExtensionDays());
    }
    
    public String getDN(final RequestDataRow dataRow) {
        // TODO validation (ECA-5235)
        return (String) dataRow.getEditValue();
    }
    
    /** Logs the message of an exception, which usually contains some message. For example: "You may not approve an action which you requested yourself" */
    private void logException(final String action, final Throwable t) {
        if (log.isDebugEnabled()) {
            log.debug("Got exception while trying to " + action + " an approval request: " + t.getMessage());
        }
    }
    
}