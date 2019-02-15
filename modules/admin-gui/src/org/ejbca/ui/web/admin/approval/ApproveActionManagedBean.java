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
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.ActionEvent;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.myfaces.renderkit.html.util.AddResource;
import org.apache.myfaces.renderkit.html.util.AddResourceFactory;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
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
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Session scoped bean for displaying information about an approval request.
 *
 * @version $Id$
 */
@ViewScoped
@ManagedBean(name="approvalActionManagedBean")
public class ApproveActionManagedBean extends BaseManagedBean {
    private static final long serialVersionUID = 1940920496104779323L;
    private static final Logger log = Logger.getLogger(ApproveActionManagedBean.class);
    private static final InternalResources intres = InternalResources.getInstance();

    private enum Action {
        APPROVE(intres.getLocalizedMessage("general.approve")), 
        REJECT(intres.getLocalizedMessage("general.reject"));

       private static List<SelectItem> selectItems;
       private final String label;

       static {
           selectItems = new ArrayList<>();
           for(Action action : Action.values()) {
               selectItems.add(new SelectItem(action, action.getLabel()));
           }
       }

       private Action(final String label) {
           this.label = label;

       }

       public String getLabel() {
           return label;
       }

       public static List<SelectItem> asSelectItems() {
           return selectItems;
       }
    }

    @EJB
    private ApprovalExecutionSessionLocal approvalExecutionSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    // Authentication check and audit log page access request
    public void initialize(ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            final boolean approveendentity = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVEENDENTITY);
            final boolean approvecaaction = getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_APPROVECAACTION);
            
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR);
            if (!approveendentity && !approvecaaction) {
                throw new AuthorizationDeniedException("Not authorized to view approval pages");
            }
        }
    }

	private String comment = "";
	private ApprovalDataVOView approvalDataVOView = new ApprovalDataVOView();
	private HashMap<Integer, String> statustext = null;
	private Map<Integer, Action> partitionActions;

	private ListDataModel<ApprovalPartitionProfileGuiObject> partitionsAuthorizedToView = null;
	private Set<Integer> partitionsAuthorizedToApprove = null;
	private ListDataModel<ApprovalPartitionProfileGuiObject> previousPartitions = null;

	public HashMap<Integer, String> getStatusText(){
	    if(statustext == null){
	    	EjbcaWebBean ejbcawebbean = EjbcaJSFHelper.getBean().getEjbcaWebBean();
	    	statustext = new HashMap<>();
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL), ejbcawebbean.getText("WAITING", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_EXPIRED), ejbcawebbean.getText("EXPIRED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED), ejbcawebbean.getText("EXPIREDANDNOTIFIED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_EXECUTED), ejbcawebbean.getText("EXECUTED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_APPROVED), ejbcawebbean.getText("APPROVED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_REJECTED), ejbcawebbean.getText("REJECTED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_EXECUTIONFAILED), ejbcawebbean.getText("EXECUTIONFAILED", true));
	    	statustext.put(Integer.valueOf(ApprovalDataVO.STATUS_EXECUTIONDENIED), ejbcawebbean.getText("EXECUTIONDENIED", true));
	    }
	    return statustext;
	}

	public ApprovalDataVOView getApproveRequestData() {
		return approvalDataVOView;
	}

	public boolean isApprovalRequestComparable() {
		return approvalDataVOView.getApproveActionDataVO().getApprovalRequest().getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_COMPARING;
	}

	public String getWindowWidth(){
		if(isApprovalRequestComparable()){
			return "1000";
		}
		return "600";
	}

    public List<ApprovalView> getApprovalViews() {
        List<ApprovalView> approvalViews = new ArrayList<>();
        if (approvalDataVOView != null && approvalDataVOView.getApproveActionDataVO().getApprovals() != null) {
            for (Approval approval : approvalDataVOView.getApproveActionDataVO().getApprovals()) {
                approvalViews.add(new ApprovalView(approval));
            }
        }
        return approvalViews;
    }

    public boolean isExistsApprovals(){
    	return approvalDataVOView.getApproveActionDataVO().getApprovals().size() >0;
    }

    public boolean isApprovable(){
    	return approvalDataVOView.getApproveActionDataVO().getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
    }

    public List<SelectItem> getActionsAvailable() {
        return Action.asSelectItems();
    }

    public Action getActionForPartition() {
        Action result = getPartitionActions().get(partitionsAuthorizedToView.getRowData().getPartitionId());
        if(result != null) {
            return result;
        } else {
            return Action.APPROVE;
        }
    }

    private Map<Integer, Action> getPartitionActions() {
        if (partitionActions == null) {
            partitionActions = new HashMap<>();
            for (Approval approval : approvalDataVOView.getApproveActionDataVO().getApprovals()) {
                if (approval.getStepId() == getCurrentStep().getStepIdentifier()) {
                    if (approval.isApproved()) {
                        partitionActions.put(approval.getPartitionId(), Action.APPROVE);
                    } else {
                        partitionActions.put(approval.getPartitionId(), Action.REJECT);
                    }
                }
            }
        }
        return partitionActions;
    }

    public void setActionForPartition(final Action action) {
        getPartitionActions().put(partitionsAuthorizedToView.getRowData().getPartitionId(), action);
    }

    public String saveState(ActionEvent event) {
        boolean closeWindow = true;
        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(approvalDataVOView.getApprovalId());
        if (approvalDataVO != null) {
            ApprovalRequest approvalRequest = approvalDataVO.getApprovalRequest();
            ApprovalProfile storedApprovalProfile = approvalRequest.getApprovalProfile();
            for (Iterator<ApprovalPartitionProfileGuiObject> iter = partitionsAuthorizedToView.iterator(); iter.hasNext(); ) {
                boolean isRejected = false;
                ApprovalPartitionProfileGuiObject approvalPartitionGuiObject = iter.next();
                Integer partitionId = approvalPartitionGuiObject.getPartitionId();
                if (partitionsAuthorizedToApprove.contains(partitionId)) {
                    try {
                        final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
                        ApprovalStep currentStep = getCurrentStep();
                        //Overwrite the stored partition in the request in order to persist metadata.
                        List<DynamicUiProperty<? extends Serializable>> updatedProperties = new ArrayList<>();
                        for (Iterator<DynamicUiProperty<? extends Serializable>> propertyIterator = approvalPartitionGuiObject.getProfilePropertyList()
                                .iterator(); propertyIterator.hasNext();) {
                            updatedProperties.add(propertyIterator.next());
                        }
                        storedApprovalProfile.addPropertiesToPartition(currentStep.getStepIdentifier(), partitionId, updatedProperties);
                        //Update any set meta data.
                        final Approval approval = new Approval(comment, currentStep.getStepIdentifier(), partitionId);
                        Action action = getPartitionActions().get(partitionId);
                        if(action != null) {
                            switch (action) {
                            case APPROVE:
                                approvalExecutionSession.approve(admin, approvalDataVOView.getApprovalId(), approval);
                                break;
                            case REJECT:
                                approvalExecutionSession.reject(admin, approvalDataVOView.getApprovalId(), approval);
                                isRejected = true;
                                break;
                            default:
                                break;
                            }
                        }
                    } catch (ApprovalRequestExpiredException e) {
                        addErrorMessage("APPROVALREQUESTEXPIRED");
                        closeWindow = false;
                    } catch (ApprovalRequestExecutionException e) {
                        addErrorMessage("ERROREXECUTINGREQUEST");
                        closeWindow = false;
                    } catch (AuthorizationDeniedException | AuthenticationFailedException e) {
                        addErrorMessage("AUTHORIZATIONDENIED");
                        closeWindow = false;
                    } catch (ApprovalException e) {
                        addErrorMessage("ERRORHAPPENDWHENAPPROVING");
                        closeWindow = false;
                    } catch (AdminAlreadyApprovedRequestException | SelfApprovalException e) {
                        addNonTranslatedErrorMessage(e);
                        closeWindow = false;
                    }
                }
                // Stop if a partition has been rejected
                if (isRejected) {
                    break;
                }
            }
            approvalSession.updateApprovalRequest(approvalDataVO.getId(), approvalRequest);
        } else {
            try {
                int status = approvalSession.getStatus(approvalDataVOView.getApprovalId());
                switch (status) {
                case ApprovalDataVO.STATUS_EXECUTED:
                case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                    addErrorMessage("REQALREADYPROCESSED");
                    break;
                case ApprovalDataVO.STATUS_EXPIRED:
                case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                    addErrorMessage("REQHASEXPIRED");
                    break;
                default:
                    break;
                }
            } catch (ApprovalException e) {
                addNonTranslatedErrorMessage(e);
            }
            closeWindow = false;
        }
        updateApprovalRequestData(approvalDataVOView.getApproveActionDataVO().getId());
        // Close window if successful
        if (closeWindow) {
            closeWindow();
        }
        return "approveaction";
    }

    private void closeWindow() {
        //Hack for closing the window after saving
        FacesContext facesContext = FacesContext.getCurrentInstance();
        //Add the Javascript to the rendered page's header for immediate execution
        AddResource addResource = AddResourceFactory.getInstance(facesContext);
        //Think of a better solution and you're free to implement it.
        addResource.addInlineScriptAtPosition(facesContext, AddResource.HEADER_BEGIN, "window.close();");
        //I'm so, so sorry. I have dishonored my dojo.
    }

    public void setUniqueId(int uniqueId) {
    	log.debug("ApproveActionSessionBean.setApprovalId setting uniqueId : " + uniqueId);
    	updateApprovalRequestData(uniqueId);
    }

    private void updateApprovalRequestData(int id){
    	Query query = new Query(Query.TYPE_APPROVALQUERY);
    	query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));
    	List<ApprovalDataVO> result;
    	try {
    		RAAuthorization raAuthorization = new RAAuthorization(EjbcaJSFHelper.getBean().getAdmin(), globalConfigurationSession,
    				authorizationSession, caSession, endEntityProfileSession);
    		result = approvalSession.query(query, 0, 1, raAuthorization.getCAAuthorizationString(),
    		        raAuthorization.getEndEntityProfileAuthorizationString(AccessRulesConstants.APPROVE_END_ENTITY));
    		if (result.size() > 0) {
    			this.approvalDataVOView = new ApprovalDataVOView(result.get(0));
    		}
    	} catch (IllegalQueryException e) {
    		addErrorMessage("INVALIDQUERY");
    	} catch (AuthorizationDeniedException e) {
    		addErrorMessage("AUTHORIZATIONDENIED");
    	}
    }

    public String getComment() {
    	return "";
    }
    public void setComment(String comment) {
    	this.comment = comment;
    }

    public int getNumberOfPartitionsInStep() {
        ApprovalStep step = getCurrentStep();
        if(step == null) {
            return -1;
        } else {
        return step.getPartitions().size();
        }
    }

    /**
     * @return the ordinal of the step currently being evaluated
     */
    public int getCurrentStepOrdinal() {
        Collection<Approval> approvals = approvalDataVOView.getApproveActionDataVO().getApprovals();
        try {
            ApprovalProfile approvalProfile = approvalDataVOView.getApprovalProfile();
            if (approvalProfile != null) {
                return approvalProfile.getOrdinalOfStepBeingEvaluated(approvals);
            } else {
                return 0;
            }
        } catch (AuthenticationFailedException e) {
            throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
        }

    }

    /**
     *
     * @return the step currently being evaluated
     */
    public ApprovalStep getCurrentStep() {
        Collection<Approval> approvals = approvalDataVOView.getApproveActionDataVO().getApprovals();
        ApprovalProfile approvalProfile = approvalDataVOView.getApprovalProfile();
        if (approvalProfile == null) {
            return null;
        } else {
            try {
                return approvalDataVOView.getApprovalProfile().getStepBeingEvaluated(approvals);
            } catch (AuthenticationFailedException e) {
                //We shouldn't have gotten here in the UI with an invalid token
                throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
            }
        }
    }

    /**
     *
     * @return all previous partitions that the current admin has view access to
     */
    public ListDataModel<ApprovalPartitionProfileGuiObject> getPreviousPartitions() {
        if (previousPartitions == null) {
            List<ApprovalPartitionProfileGuiObject> authorizedPartitions = new ArrayList<>();
            ApprovalProfile approvalProfile = approvalDataVOView.getApprovalRequest().getApprovalProfile();
            if (approvalProfile != null) {
                ApprovalStep step = approvalProfile.getFirstStep();
                ApprovalStep currentStep = getCurrentStep();
                while (step != null) {
                    if (currentStep != null && step.equals(currentStep)) {
                        break;
                    }
                    for (ApprovalPartition approvalPartition : step.getPartitions().values()) {
                        try {
                            if (approvalDataVOView.getApprovalProfile().canViewPartition(getAdmin(), approvalPartition)) {
                                authorizedPartitions.add(new ApprovalPartitionProfileGuiObject(
                                        approvalDataVOView.getApprovalProfile().getApprovalProfileTypeIdentifier(),
                                        approvalPartition.getPartitionIdentifier(),
                                        approvalPartition.getProperty(PartitionedApprovalProfile.PROPERTY_NAME).getValueAsString(),
                                        getPartitionProperties(approvalPartition)));
                            }
                        } catch (AuthenticationFailedException e) {
                            //We shouldn't have gotten here in the UI with an invalid token
                            throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
                        }
                    }
                    step = approvalDataVOView.getApprovalProfile().getStep(step.getNextStep());
                }
            }
            previousPartitions = new ListDataModel<>(authorizedPartitions);
        }
        return previousPartitions;

    }

    /**
     *
     * @return all partitions that the current admin has view access to
     */
    public ListDataModel<ApprovalPartitionProfileGuiObject> getApprovalPartitions() {
        if (partitionsAuthorizedToView == null) {
            List<ApprovalPartitionProfileGuiObject> authorizedPartitions = new ArrayList<>();
            partitionsAuthorizedToApprove = new HashSet<>();
            //Make sure we're not reading stale data
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(approvalDataVOView.getApprovalProfile().getProfileId());
            if (getCurrentStep() != null) {
                final ApprovalStep approvalStep = approvalProfile.getStep(getCurrentStep().getStepIdentifier());
                for (Integer approvalPartitionId : getCurrentStep().getPartitions().keySet()) {
                    ApprovalPartition approvalPartition = approvalStep.getPartition(approvalPartitionId);
                    if (approvalPartition != null) {
                        try {
                            if (approvalDataVOView.getApprovalProfile().canViewPartition(getAdmin(), approvalPartition)) {
                                final DynamicUiProperty<? extends Serializable> nameProperty = approvalPartition
                                        .getProperty(PartitionedApprovalProfile.PROPERTY_NAME);
                                authorizedPartitions.add(new ApprovalPartitionProfileGuiObject(
                                        approvalDataVOView.getApprovalProfile().getApprovalProfileTypeIdentifier(),
                                        approvalPartition.getPartitionIdentifier(), nameProperty != null ? nameProperty.getValueAsString() : "-",
                                        getPartitionProperties(approvalPartition)));
                            }
                            if (approvalDataVOView.getApprovalProfile().canApprovePartition(getAdmin(), approvalPartition)) {
                                partitionsAuthorizedToApprove.add(approvalPartition.getPartitionIdentifier());
                            }
                        } catch (AuthenticationFailedException e) {
                            //We shouldn't have gotten here in the UI with an invalid token
                            throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
                        }
                    }
                }
            }
            partitionsAuthorizedToView = new ListDataModel<>(authorizedPartitions);

        }
        return partitionsAuthorizedToView;
    }

    public boolean canApprovePartition(ApprovalPartitionProfileGuiObject partition) {
        if(partitionsAuthorizedToApprove == null) {
            getActionForPartition();
        }
        if(!partitionsAuthorizedToApprove.contains(partition.getPartitionId())) {
            return false;
        }
        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(approvalDataVOView.getApprovalId());
        if (approvalDataVO == null) {
            return false;
        }
        if(approvalDataVO.getApprovalRequest().isEditedByMe(getAdmin())) {
            return false;
        }

        if(approvalDataVO.getApprovalRequest().getRequestAdmin().equals(getAdmin())) {
            return false;
        }

        Collection<Approval> approvals = approvalDataVO.getApprovals();
        for(Approval approval : approvals) {
            if(approval.getAdmin().equals(getAdmin())) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return true if the current admin has access to approve any partitions at all
     */
    public boolean canApproveAnyPartitions() {
        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(approvalDataVOView.getApprovalId());
        boolean hasAlreadyApproved = false;
        for (ApprovalView approvalView : getApprovalViews()) {
            if (approvalView.getApprovalAdmin().equals(getAdmin().toString())) {
                hasAlreadyApproved = true;
                break;
            }
        }
        // Check that there are are partitions to approve, that the request didn't originate from the current admin and that
        // the current admin hasn't previously approved any part of the request
        return !partitionsAuthorizedToApprove.isEmpty()
                && (approvalDataVO != null ? !approvalDataVO.getApprovalRequest().getRequestAdmin().equals(getAdmin()) : true)
                && !hasAlreadyApproved;
    }

    /**
     * Checks whether a certain property was defined in the approval profile to be read only, i.e. displayed but not changeable.
     *
     * @param propertyName the name of the property
     * @return true if the property was defined as read-only, false otherwise.
     */
    public boolean isPropertyReadOnly(final String propertyName) {
        return approvalDataVOView.getApprovalProfile().getReadOnlyProperties().contains(propertyName);
    }

    /**
     * Extract the partition properties, and fill in all and any placeholders. Also cull any properties set to be hidden.
     *
     * @return a list of dynamic properties
     */
    private List<DynamicUiProperty<? extends Serializable>> getPartitionProperties(ApprovalPartition approvalPartition) {
        Set<String> hiddenPropertyNames = approvalDataVOView.getApprovalProfile().getHiddenProperties();
        List<DynamicUiProperty<? extends Serializable>> propertyList = new ArrayList<>();
        for (String propertyName : approvalPartition.getPropertyList().keySet()) {
            if (!hiddenPropertyNames.contains(propertyName)) {
                DynamicUiProperty<? extends Serializable> propertyClone = new DynamicUiProperty<>(
                        approvalPartition.getPropertyList().get(propertyName));
                switch (propertyClone.getPropertyCallback()) {
                case ROLES:
                    final List<Role> allAuthorizedRoles = roleSession.getAuthorizedRoles(getAdmin());
                    final List<RoleInformation> roleRepresentations = new ArrayList<>();
                    for (final Role role : allAuthorizedRoles) {
                        if (AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVEENDENTITY)
                                || AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                            try {
                                final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAdmin(), role.getRoleId());
                                roleRepresentations.add(RoleInformation.fromRoleMembers(role.getRoleId(), role.getNameSpace(), role.getRoleName(), roleMembers));
                            } catch (AuthorizationDeniedException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Not authorized to members of authorized role '"+role.getRoleNameFull()+"' (?):" + e.getMessage());
                                }
                            }
                        }
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
        return propertyList;
    }

    /**
     * Updates approval request based on the changes in approval profile.
     * Also updates corresponding approval profile in the approval profile session.
     *
     * @param uniqueId id of approval request data to be updated.
     */
    public void updateApprovalRequest(final int uniqueId) {

        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(approvalDataVOView.getApprovalId());

        if (approvalDataVO == null) {
            log.warn("Approval request already expired or invalid!");
            return;
        }

        ApprovalRequest currentApprovalRequest = approvalDataVO.getApprovalRequest();

        ApprovalProfile approvalProfileFromRequest = currentApprovalRequest.getApprovalProfile();
        ApprovalProfile approvalProfileFromSession = approvalProfileSession.getApprovalProfile(currentApprovalRequest.getApprovalProfile().getProfileId().intValue());

        // Set the updated approval profile in current request.
        currentApprovalRequest.setApprovalProfile(updateApprovalProfile(approvalProfileFromRequest));
        approvalSession.updateApprovalRequest(approvalDataVO.getId(), currentApprovalRequest);

        // To update the roles and make authorization possible
        try {
            approvalProfileSession.changeApprovalProfile(getAdmin(), updateApprovalProfile(approvalProfileFromSession));
        } catch (AuthorizationDeniedException e) {
            log.info("Not authorized to change approval profile!" + e);
        }

        updateApprovalRequestData(uniqueId);
    }

    /**
     * Updates the approval profile based on the role changes in session.
     *
     * @param approvalProfile
     * @return
     */
    private ApprovalProfile updateApprovalProfile(final ApprovalProfile approvalProfile) {

        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            for (ApprovalPartition approvalPartition : approvalStep.getPartitions().values()) {
                for (DynamicUiProperty<? extends Serializable> property : approvalPartition.getPropertyList().values()) {

                    DynamicUiProperty<? extends Serializable> propertyClone = new DynamicUiProperty<>(property);

                    if (property.getName().equals(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_VIEW_RIGHTS)
                            || property.getName().equals(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS)) {

                        List<RoleInformation> updatedRoleInformation = new ArrayList<>();

                        for (final Serializable value : property.getPossibleValues()) {
                            RoleInformation roleInfo = (RoleInformation) value;
                            updatedRoleInformation.addAll(updateRoleMembers(roleInfo));
                        }

                        if (!updatedRoleInformation.contains(propertyClone.getDefaultValue())) {
                            //Add the default, because it makes no sense why it wouldn't be there. Also, it may be a placeholder for something else.
                            updatedRoleInformation.add(0, (RoleInformation) propertyClone.getDefaultValue());
                        }

                        propertyClone.setPossibleValues(updatedRoleInformation);
                        updateEncodedValues(propertyClone, property);

                        approvalPartition.removeProperty(property.getName());
                        approvalPartition.addProperty(propertyClone);

                        approvalStep.removePropertyFromPartition(approvalPartition.getPartitionIdentifier(), property.getName());
                        approvalStep.setPropertyToPartition(approvalPartition.getPartitionIdentifier(), propertyClone);

                        approvalProfile.removePropertyFromPartition(approvalStep.getStepIdentifier(), approvalPartition.getPartitionIdentifier(),
                                property.getName());
                        approvalProfile.addPropertyToPartition(approvalStep.getStepIdentifier(), approvalPartition.getPartitionIdentifier(),
                                propertyClone);
                    }
                }
            }
        }

        return approvalProfile;
    }

     /**
      * Update role members based on latest from role member session.
      *
      * @param roleToUpdate
      * @return list of updated role infos.
      */
     private List<RoleInformation> updateRoleMembers(final RoleInformation roleToUpdate) {
         final List<Role> allAuthorizedRoles = roleSession.getAuthorizedRoles(getAdmin());
         final List<RoleInformation> roleRepresentations = new ArrayList<>();
         for (final Role role : allAuthorizedRoles) {
             if (role.getRoleId() == roleToUpdate.getIdentifier()
                     && (AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVEENDENTITY)
                             || AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVECAACTION))) {
                 try {
                     final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAdmin(), role.getRoleId());
                     roleRepresentations.add(RoleInformation.fromRoleMembers(role.getRoleId(), role.getNameSpace(), role.getRoleName(), roleMembers));
                 } catch (AuthorizationDeniedException e) {
                     if (log.isDebugEnabled()) {
                         log.debug("Not authorized to members of authorized role '" + role.getRoleNameFull() + "' (?):" + e.getMessage());
                     }
                 }
             }
         }
         return roleRepresentations;
     }

     /**
      * Updates the encoded values of propertyClone if
      * there has been a change in the role members of the
      * any of the roles which were selected in the list box
      * before the change.
      * Uses property identifier as a base for comparison.
      *
      * @param propertyClone updated property
      * @param property current property
      */
     private void updateEncodedValues(final DynamicUiProperty<? extends Serializable> propertyClone,
             final DynamicUiProperty<? extends Serializable> property) {

         List<Integer> currentIds = new ArrayList<>();

         for (final String value : property.getEncodedValues()) {
             RoleInformation roleInfo = (RoleInformation) DynamicUiProperty.getAsObject(value);
             currentIds.add(roleInfo.getIdentifier());
         }

         List<String> finalListOfEncodedValues = new ArrayList<>();

         for (final Serializable value : propertyClone.getPossibleValues()) {
             RoleInformation roleInformation = (RoleInformation) value;

             if (currentIds.contains(roleInformation.getIdentifier())) {
                 finalListOfEncodedValues.add(property.getAsEncodedValue(property.getType().cast(value)));
             }
         }

         // Here we update the propertyClone set of encoded values.
         try {
             propertyClone.setEncodedValues(finalListOfEncodedValues);
         } catch (PropertyValidationException e) {
             log.error("Invalid propery value while setting the encoded values for property clone!" + e);
         }
     }
}
