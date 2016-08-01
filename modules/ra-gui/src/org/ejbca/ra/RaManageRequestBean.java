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
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
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
import org.ejbca.core.model.era.RaApprovalEditRequest;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaApprovalResponseRequest;
import org.ejbca.core.model.era.RaApprovalResponseRequest.Action;
import org.ejbca.core.model.era.RaEditableRequestData;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.ApprovalRequestGUIInfo.RequestDataRow;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;

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
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    
    private ApprovalRequestGUIInfo requestInfo;
    private RaApprovalRequestInfo requestData;
    private boolean editing = false;
    private Map<Integer, List<DynamicUiProperty<? extends Serializable>> > currentPartitionsProperties = null;
    List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> partitionsAuthorizedToView = null;
    Set<Integer> partitionsAuthorizedToApprove = null;
    private String fromTab = null;
    
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
            fromTab = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("fromTab");
        }
    }
    
    private void reloadRequest() {
        loadRequest(requestData.getId());
    }
    
    public ApprovalRequestGUIInfo getRequest() {
        initializeRequestInfo();
        if (requestInfo == null) {
            throw new IllegalStateException("Internal Error: requestInfo was null");
        }
        return requestInfo;
    }
    
    public String getPageTitle() {
        return raLocaleBean.getMessage("view_request_page_title", getRequest().getDisplayName());
    }
    
    public String getFromTab() {
        return fromTab;
    }
    
    public boolean isViewDataVisible() { return !editing; }
    public boolean isEditDataVisible() { return editing; }
    public boolean isStatusVisible() { return !editing; }
    public boolean isPreviousStepsVisible() { return !editing && !getRequest().getPreviousSteps().isEmpty(); }
    public boolean isApprovalVisible() { return !editing; } // even if approval is not possible, we still show a message explaining why it's not.
    
    public List<DynamicUiProperty<? extends Serializable>> getPartitionProperties(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiPartition) {
        if (guiPartition == null) {
            // JBoss EAP 6.4 seems to make calls EL method calls one time extra, with a null parameter, once per page rendering
            log.debug("Ignored call to getPartitionProperties with null parameter");
            return new ArrayList<>();
        }
        final ApprovalProfile approvalProfile = getRequest().request.getApprovalProfile();
        final ApprovalStep step = approvalProfile.getStep(guiPartition.getStepId());
        final ApprovalPartition partition = step.getPartition(guiPartition.getPartitionId());
        return getPartitionProperties(approvalProfile, partition);
    }
    
    public List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> getPartitions() {
        if (partitionsAuthorizedToView == null) {
            List<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject> authorizedPartitions = new ArrayList<>();
            partitionsAuthorizedToApprove = new HashSet<>();
            final ApprovalStep step = getRequest().request.getNextApprovalStep();
            final ApprovalProfile approvalProfile = getRequest().request.getApprovalProfile();
            if (step != null) {
                for (ApprovalPartition approvalPartition : step.getPartitions().values()) {
                    try {
                        if (approvalProfile.canViewPartition(raAuthenticationBean.getAuthenticationToken(), approvalPartition)) {
                            ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partitionGuiObject = 
                                    new ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject(step.getStepIdentifier(),
                                    approvalPartition.getPartitionIdentifier(), getPartitionProperties(approvalProfile, approvalPartition));
                            authorizedPartitions.add(partitionGuiObject);
                        }
                        if (approvalProfile.canApprovePartition(raAuthenticationBean.getAuthenticationToken(), approvalPartition)) {
                            partitionsAuthorizedToApprove.add(approvalPartition.getPartitionIdentifier());
                        }
                    } catch (AuthenticationFailedException e) {
                        //We shouldn't have gotten here in the UI with an invalid token
                        throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
                    }
                }
            }
            partitionsAuthorizedToView = new ArrayList<ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject>(authorizedPartitions);

        }
        return partitionsAuthorizedToView;
        
    }

    /** 
     * @return true if there already exists an approval for this partition 
     */
    public boolean isPartitionHandled(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partition) {
        final ApprovalDataVO advo = getRequest().request.getApprovalData();
        Collection<Approval> approvals = advo.getApprovals();
        for(Approval approval : approvals) {
            if((approval.getStepId()==partition.getStepId()) && (approval.getPartitionId()==partition.getPartitionId())) {
                return true;
            }
        }
        return false;
    }
    public boolean canApproveParition(final ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject partition) {
        if(partitionsAuthorizedToApprove == null) {
            getPartitions();
        }
        return partitionsAuthorizedToApprove.contains(partition.getPartitionId());
    }
    public boolean isPropertyReadOnly(String propertyName) {
        return getRequest().request.getApprovalProfile().getReadOnlyProperties().contains(propertyName);
    }
    
    /**
     * Extract the partition properties, and fill in all and any placeholders. Also cull any properties set to be hidden.
     * 
     * @return a list of dynamic properties 
     */
    private List<DynamicUiProperty<? extends Serializable>> getPartitionProperties(final ApprovalProfile approvalProfile, ApprovalPartition approvalPartition) {
        if(currentPartitionsProperties == null || !currentPartitionsProperties.containsKey(approvalPartition.getPartitionIdentifier())) {
            Set<String> hiddenPropertyNames = approvalProfile.getHiddenProperties();    
            List<DynamicUiProperty<? extends Serializable>> propertyList = new ArrayList<>();
            for (String propertyName : approvalPartition.getPropertyList().keySet()) {
                if (!hiddenPropertyNames.contains(propertyName)) {
                    DynamicUiProperty<? extends Serializable> propertyClone = new DynamicUiProperty<>(
                            approvalPartition.getPropertyList().get(propertyName));
                    switch (propertyClone.getPropertyCallback()) {
                    case ROLES:
                        List<RoleData> allAuthorizedRoles = roleAccessSession.getAllAuthorizedRoles(raAuthenticationBean.getAuthenticationToken());
                        List<RoleInformation> roleRepresentations = new ArrayList<>();
                        for (RoleData role : allAuthorizedRoles) {
                            RoleInformation identifierNamePair = new RoleInformation(role.getPrimaryKey(), role.getRoleName(),
                                    new ArrayList<>(role.getAccessUsers().values()));
                            roleRepresentations.add(identifierNamePair);
                        }
                        if (!roleRepresentations.contains(propertyClone.getDefaultValue())) {
                            //Add the default, because it makes no sense why it wouldn't be there. Also, it may be a placeholder for something else. 
                            roleRepresentations.add(0, (RoleInformation) propertyClone.getDefaultValue());
                        }
                        propertyClone.setPossibleValues(roleRepresentations);
                        break;
                    case NONE:
                        break;
                    default:
                        break;
                    }
                    propertyList.add(propertyClone);
                }
            }
            
            if(currentPartitionsProperties == null) {
                currentPartitionsProperties = new HashMap<Integer, List<DynamicUiProperty<? extends Serializable>> >();
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
                    partition.getPartitionIdentifier(), getPartitionProperties(requestData.getApprovalProfile(), partition)));
        }
        return ret;
    }
    
    public String getStepInfoText() {
        final List<String> roles = new ArrayList<>(requestData.getNextStepAllowedRoles());
        Collections.sort(roles);
        return raLocaleBean.getMessage("view_request_page_step_of", getRequest().getCurrentStepOrdinal(), getRequest().getStepCount(), StringUtils.join(roles, ", "));
    }
    
    public String getCantApproveReason() {
        if (getRequest().isExpired()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_expired");
        } else if (getRequest().isPendingExecution()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_pending_execution");
        } else if (getRequest().isExecuted()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_already_executed");
        } else if (getRequest().isExecutionFailed()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_already_executed_failed");
        } else if (!getRequest().isWaitingForApproval()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_not_waiting");
        } else if (getRequest().isPending()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_pending");
        } else if (getRequest().isEditedByMe()) {
            return raLocaleBean.getMessage("view_request_page_cannot_approve_edited_by_me");
        } else {
            return raLocaleBean.getMessage("view_request_page_cannot_approve");
        }
    }
    
    private ApprovalDataVO getApprovalData(AuthenticationToken authenticationToken, final int id) {
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));
        
        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalSession.query(authenticationToken, query, 0, 100, "", ""); // authorization checks are performed afterwards
        } catch (AuthorizationDeniedException e) {
            // Not currently ever thrown by query()
            throw new IllegalStateException(e);
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval request failed: " + e.getMessage(), e);
        }
        
        if (approvals.isEmpty()) {
            return null;
        }
        
        return approvals.iterator().next();
    }
    
    
    private RaApprovalResponseRequest buildApprovalResponseRequest(final Action action, ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiParition, 
                ApprovalProfile storedApprovalProfile, ApprovalDataVO advo) {
        ApprovalStep step = storedApprovalProfile.getStep(guiParition.getStepId());
        ApprovalPartition partition = step.getPartition(guiParition.getPartitionId());
        
        List<DynamicUiProperty<? extends Serializable>> updatedProperties =  getPartitionProperties(storedApprovalProfile, partition);
        storedApprovalProfile.addPropertiesToPartition(step.getStepIdentifier(), partition.getPartitionIdentifier(), updatedProperties);
        
        ApprovalRequest request = advo.getApprovalRequest();
        request.setApprovalProfile(storedApprovalProfile);
        approvalSession.updateApprovalRequest(advo.getId(), request);

        final int id = getRequest().request.getId();
        final int stepId = step.getStepIdentifier();
        final int partitionId = partition.getPartitionIdentifier();
        final RaApprovalResponseRequest approval = new RaApprovalResponseRequest(id, stepId, partitionId,  "", action); // TODO comment field. should it be here for partitioned approvals also?
        return approval;
    }
    
    public void approve() throws AuthorizationDeniedException, AuthenticationFailedException {
        
        final ApprovalDataVO advo = getApprovalData(raAuthenticationBean.getAuthenticationToken(), getRequest().request.getId());
        ApprovalProfile storedApprovalProfile = advo.getApprovalRequest().getApprovalProfile();
        
        for(ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiParition : partitionsAuthorizedToView) {
            if(partitionsAuthorizedToApprove.contains(guiParition.getPartitionId())) {
                final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.APPROVE, guiParition, storedApprovalProfile, advo);
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
        
        final ApprovalDataVO advo = getApprovalData(raAuthenticationBean.getAuthenticationToken(), getRequest().request.getId());
        ApprovalProfile storedApprovalProfile = advo.getApprovalRequest().getApprovalProfile();
        
        for(ApprovalRequestGUIInfo.ApprovalPartitionProfileGuiObject guiParition : partitionsAuthorizedToView) {
            if(partitionsAuthorizedToApprove.contains(guiParition.getPartitionId())) {

                final RaApprovalResponseRequest responseReq = buildApprovalResponseRequest(Action.REJECT, guiParition, storedApprovalProfile, advo);
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
        requestData = raMasterApiProxyBean.editApprovalRequest(raAuthenticationBean.getAuthenticationToken(), editReq);
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean);
        editing = false;
    }
    
    public void cancelEdit() {
        if (!editing) {
            throw new IllegalStateException();
        }
        // Restore everything
        requestData = raMasterApiProxyBean.getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), requestData.getId());
        requestInfo = new ApprovalRequestGUIInfo(requestData, raLocaleBean);
        editing = false;
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