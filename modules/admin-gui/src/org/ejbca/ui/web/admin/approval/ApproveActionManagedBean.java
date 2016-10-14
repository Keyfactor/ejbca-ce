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
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.apache.myfaces.renderkit.html.util.AddResource;
import org.apache.myfaces.renderkit.html.util.AddResourceFactory;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
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
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
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
        APPROVE(intres.getLocalizedMessage("general.approve")), REJECT(intres.getLocalizedMessage("general.reject")), NO_ACTION(
                intres.getLocalizedMessage("general.noaction"));

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
    private RoleAccessSessionLocal roleAccessSession;
    
    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private ComplexAccessControlSessionLocal complexAccessControlSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    
	private String comment = "";
	private ApprovalDataVOView approvalDataVOView = new ApprovalDataVOView();      
	private HashMap<Integer, String> statustext = null;
	private Map<Integer, Action> partitionActions;
	
	ListDataModel<ApprovalPartitionProfileGuiObject> partitionsAuthorizedToView = null;
	Set<Integer> partitionsAuthorizedToApprove = null;
	ListDataModel<ApprovalPartitionProfileGuiObject> previousPartitions = null;

	public HashMap<Integer, String> getStatusText(){
	    if(statustext == null){
	    	EjbcaWebBean ejbcawebbean = EjbcaJSFHelper.getBean().getEjbcaWebBean();
	    	statustext = new HashMap<Integer, String>();
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
        List<ApprovalView> approvalViews = new ArrayList<ApprovalView>();
        if (approvalDataVOView != null && approvalDataVOView.getApproveActionDataVO().getApprovals() != null) {
            for(Approval approval : approvalDataVOView.getApproveActionDataVO().getApprovals()) {
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
            return Action.NO_ACTION;
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
        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(getAdmin(), approvalDataVOView.getApprovalId());
        ApprovalRequest approvalRequest = approvalDataVO.getApprovalRequest();
        ApprovalProfile storedApprovalProfile = approvalRequest.getApprovalProfile();
        for (Iterator<ApprovalPartitionProfileGuiObject> iter = partitionsAuthorizedToView.iterator(); iter.hasNext(); ) {
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
                            updateApprovalRequestData(approvalDataVOView.getApproveActionDataVO().getId());
                            break;
                        case REJECT:
                            approvalExecutionSession.reject(admin, approvalDataVOView.getApprovalId(), approval);
                            updateApprovalRequestData(approvalDataVOView.getApproveActionDataVO().getId());
                            break;
                        case NO_ACTION:
                            break;
                        default:
                            break;
                        }
                    }
                } catch (ApprovalRequestExpiredException e) {
                    addErrorMessage("APPROVALREQUESTEXPIRED");
                } catch (ApprovalRequestExecutionException e) {
                    addErrorMessage("ERROREXECUTINGREQUEST");
                } catch (AuthorizationDeniedException | AuthenticationFailedException e) {
                    addErrorMessage("AUTHORIZATIONDENIED");
                } catch (ApprovalException e) {
                    addErrorMessage("ERRORHAPPENDWHENAPPROVING");
                } catch (AdminAlreadyApprovedRequestException | SelfApprovalException e) {
                    addErrorMessage(e.getMessage());
                }
            }
        }
        approvalSession.updateApprovalRequest(approvalDataVO.getId(), approvalRequest);
        //Hack for closing the window after saving
        FacesContext facesContext = FacesContext.getCurrentInstance(); 
        //Yeah. I know. 
        String javaScriptText = "window.close();"; 
        //Add the Javascript to the rendered page's header for immediate execution 
        AddResource addResource = AddResourceFactory.getInstance(facesContext); 
        //Think of a better solution and you're free to implement it.
        addResource.addInlineScriptAtPosition(facesContext, AddResource.HEADER_BEGIN, javaScriptText);   
        //I'm so, so sorry. I have dishonored my dojo. 
        return "approveaction";
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
    				accessControlSession, complexAccessControlSession, caSession, endEntityProfileSession, 
    				approvalProfileSession);
    		result = approvalSession.query( EjbcaJSFHelper.getBean().getAdmin(), query, 0, 1, raAuthorization.getCAAuthorizationString(), 
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
                                authorizedPartitions.add(
                                        new ApprovalPartitionProfileGuiObject(approvalDataVOView.getApprovalProfile().getApprovalProfileIdentifier(),
                                                approvalPartition.getPartitionIdentifier(), getPartitionProperties(approvalPartition)));
                            }
                        } catch (AuthenticationFailedException e) {
                            //We shouldn't have gotten here in the UI with an invalid token
                            throw new IllegalStateException("Trying to perform an approval with an invalid authenticatin token.", e);
                        }
                    }
                    step = approvalDataVOView.getApprovalProfile().getStep(step.getNextStep());
                }
            }
            previousPartitions = new ListDataModel<ApprovalPartitionProfileGuiObject>(authorizedPartitions);
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
            if (getCurrentStep() != null) {
                for (ApprovalPartition approvalPartition : getCurrentStep().getPartitions().values()) {
                    try {
                        if (approvalDataVOView.getApprovalProfile().canViewPartition(getAdmin(), approvalPartition)) {
                            authorizedPartitions
                                    .add(new ApprovalPartitionProfileGuiObject(approvalDataVOView.getApprovalProfile().getApprovalProfileIdentifier(),
                                            approvalPartition.getPartitionIdentifier(), getPartitionProperties(approvalPartition)));
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
            partitionsAuthorizedToView = new ListDataModel<ApprovalPartitionProfileGuiObject>(authorizedPartitions);

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
        
        ApprovalDataVO approvalDataVO = approvalSession.findNonExpiredApprovalRequest(getAdmin(), approvalDataVOView.getApprovalId());
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
     * 
     * @return true if the current admin has access to approve any partitions at all
     */
    public boolean canApproveAnyPartitions() {
        return !partitionsAuthorizedToApprove.isEmpty();
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
                    List<RoleData> allAuthorizedRoles = roleAccessSession.getAllAuthorizedRoles(getAdmin());
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
        return propertyList;
    }
    
     
}
