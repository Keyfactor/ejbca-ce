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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import javax.faces.model.ListDataModel;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.util.EjbLocalHelper;
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
public class ApproveActionManagedBean extends BaseManagedBean {

    public class ApprovalStepGuiInfo {
        private int stepId;
        private String metadataInstruction;
        private int metadataOptionsType;
        private List<String> metadataOptions;
        private String metadataOptionValue;
        private List<String> metadataOptionValueList;
        private String metadataNote;
        private boolean approved;
        
        public ApprovalStepGuiInfo(ApprovalStep step) {
            this.stepId = step.getStepId();
            this.metadataInstruction = step.getMetadata().getInstruction();
            this.metadataOptions = step.getMetadata().getOptions();
            this.metadataOptionsType = step.getMetadata().getOptionsType();
            this.metadataOptionValue = step.getMetadata().getOptionValue();
            this.metadataNote = step.getMetadata().getOptionNote();
            this.approved = (step.getApprovalStatus()==ApprovalDataVO.STATUS_APPROVED);
        }
        
        public int getStepId() { return stepId; }
        public String getMetadataInstruction() { return metadataInstruction; }
        public int getMetadataOptionsType() { return metadataOptionsType; }
        public List<String> getMetadataOptions() { return metadataOptions; }
        public String getMetadataOptionValue() { return metadataOptionValue; }
        public void setMetadataOptionValue(String value) { metadataOptionValue=value; }
        public List<String> getMetadataOptionValueList() { return metadataOptionValueList; }
        public void setMetadataOptionValueList(List<String> value) { metadataOptionValueList=value; }
        public String getMetadataNote() { return metadataNote; }
        public void setMetadataNote(String note) { metadataNote=note; }
        public boolean getApproved() { return approved; }
    }
    
    private static final long serialVersionUID = 1940920496104779323L;
    private static final Logger log = Logger.getLogger(ApproveActionManagedBean.class);
	private final EjbLocalHelper ejb = new EjbLocalHelper();
	private String comment = "";
	private ApprovalDataVOView approveRequestData = new ApprovalDataVOView();      
	private HashMap<Integer, String> statustext = null;
	private ListDataModel<ApprovalStepGuiInfo> approvalStepsList = null;
	private int currentStepId = 0;

	public  HashMap<Integer, String> getStatusText(){
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
		return approveRequestData;
	}

	public boolean isApprovalRequestComparable() {		
		return approveRequestData.getApproveActionDataVO().getApprovalRequest().getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_COMPARING;
	}

	public String getWindowWidth(){
		if(isApprovalRequestComparable()){
			return "1000";
		}
		return "600";	
	}

    public List<ApprovalView> getApprovalViews() {
        List<ApprovalView> approvalViews = new ArrayList<ApprovalView>();
        if (approveRequestData != null && approveRequestData.getApproveActionDataVO().getApprovals() != null) {
            Iterator<Approval> iter = approveRequestData.getApproveActionDataVO().getApprovals().iterator();
            while (iter.hasNext()) {
                approvalViews.add(new ApprovalView((Approval) iter.next()));
            }
        }
        return approvalViews;
    }
    public void setApprovalViews(List<ApprovalView> list){}
   
    public boolean isExistsApprovals(){
    	return approveRequestData.getApproveActionDataVO().getApprovals().size() >0;
    }

    public boolean isExistApprovalSteps() {
        return getApprovalStepsList().iterator().hasNext();
    }
    
    public ListDataModel<ApprovalStepGuiInfo> getApprovalStepsList() {
        if (approvalStepsList == null) {
            final List<ApprovalStepGuiInfo> guiParts = new ArrayList<ApprovalStepGuiInfo>();
            final ApprovalStep nextStep = getApproveRequestData().getApprovalRequest().getNextUnhandledAppprovalStep();
            if(nextStep.canSeePreviousSteps()) {
                final List<ApprovalStep> approvedSteps = getApproveRequestData().getApprovalRequest().getApprovedApprovalSteps();
                for(ApprovalStep step : approvedSteps) {
                    guiParts.add(new ApprovalStepGuiInfo(step));
                }
            }
            guiParts.add(new ApprovalStepGuiInfo(nextStep));
            approvalStepsList = new ListDataModel<ApprovalStepGuiInfo>(guiParts);
            currentStepId = nextStep.getStepId();
        }
        return approvalStepsList;
    }
    
    public boolean isApprovable(){
    	if(approveRequestData.getApproveActionDataVO().getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
    		return true;
    	}
    	return false;
    }

   
    public String approve() {
        
        final boolean isNrOfApprovalProfile = getApproveRequestData().getApprovalRequest().getApprovalProfile().getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals;
        ApprovalStep step = getApprovalStep();

        if((step==null) && (!isNrOfApprovalProfile)) {
            addErrorMessage("No Approval Steps were found");
        } else {
            final Approval approval = new Approval(comment);
            try {		   
                final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
                ejb.getApprovalExecutionSession().approve(admin, approveRequestData.getApprovalId(), approval, step, isNrOfApprovalProfile);
                updateApprovalRequestData(approveRequestData.getApproveActionDataVO().getId());
            } catch (ApprovalRequestExpiredException e) {
                addErrorMessage("APPROVALREQUESTEXPIRED");
            } catch (ApprovalRequestExecutionException e) {
                addErrorMessage("ERROREXECUTINGREQUEST");
            } catch (AuthorizationDeniedException e) {
                addErrorMessage("AUTHORIZATIONDENIED");
            } catch (ApprovalException e) {
                addErrorMessage("ERRORHAPPENDWHENAPPROVING");
            } catch (AdminAlreadyApprovedRequestException | SelfApprovalException e) {
                addErrorMessage(e.getMessage());
            }
        }
    	return "approveaction";
    }

    public String reject(){
    	final Approval approval = new Approval(comment);
    	try {
    		final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    		ejb.getApprovalSession().reject(admin,  approveRequestData.getApprovalId(), approval);
    		updateApprovalRequestData(approveRequestData.getApproveActionDataVO().getId());
    	} catch (ApprovalRequestExpiredException e) {
    		addErrorMessage("APPROVALREQUESTEXPIRED");
    	} catch (AuthorizationDeniedException e) {
    		addErrorMessage("AUTHORIZATIONDENIED");
    	} catch (ApprovalException e) {
    		addErrorMessage("ERRORHAPPENDWHENAPPROVING");
    	} catch (AdminAlreadyApprovedRequestException e) {
    		addErrorMessage(e.getMessage());
    	}
    	return "approveaction";
    }
    
    private ApprovalStep getApprovalStep() {
        if(getApproveRequestData().getApprovalRequest().getApprovalProfile().getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
            return null;
        }
        ListDataModel<ApprovalStepGuiInfo> guiSteps = getApprovalStepsList();
        ApprovalRequest approvalRequest = getApproveRequestData().getApprovalRequest();
        for(ApprovalStepGuiInfo guiStep : guiSteps) {
            if(guiStep.getStepId() == currentStepId) {
                String metadataOptionsValue = "";
                if(guiStep.getMetadataOptionsType()==ApprovalStep.METADATATYPE_CHECKBOX) {
                    List<String> data = guiStep.getMetadataOptionValueList();
                    for(String p : data) {
                        metadataOptionsValue += p + "; " ;
                    }
                    metadataOptionsValue = metadataOptionsValue.substring(0, metadataOptionsValue.length()-3);
                } else {
                    metadataOptionsValue = guiStep.getMetadataOptionValue();
                }
                approvalRequest.updateApprovalStepMetadata(currentStepId, 
                        guiStep.getMetadataOptionValue(), guiStep.getMetadataNote());
                return approvalRequest.getApprovalStep(currentStepId);
            }
        }
        return null;
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
    		RAAuthorization raAuthorization = new RAAuthorization(EjbcaJSFHelper.getBean().getAdmin(), ejb.getGlobalConfigurationSession(),
    				ejb.getAccessControlSession(), ejb.getComplexAccessControlSession(), ejb.getCaSession(), ejb.getEndEntityProfileSession(), 
    				ejb.getApprovalProfileSession());
    		result = ejb.getApprovalSession().query( EjbcaJSFHelper.getBean().getAdmin(), query, 0, 1, raAuthorization.getCAAuthorizationString(), 
    		        raAuthorization.getEndEntityProfileAuthorizationString(AccessRulesConstants.APPROVE_END_ENTITY), 
    		        raAuthorization.getApprovalProfileAuthorizationString());
    		if (result.size() > 0) {
    			this.approveRequestData = new ApprovalDataVOView(result.get(0));
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
}
