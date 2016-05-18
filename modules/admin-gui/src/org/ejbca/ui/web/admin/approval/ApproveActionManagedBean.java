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
import org.ejbca.core.model.approval.ApprovalStepMetadata;
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

    public class MetadataGuiInfo {
        private int metadataId;
        private String instruction;
        private int optionsType;
        private List<String> options;
        private String optionValue;
        private List<String> optionValueList;
        private String note;
        public MetadataGuiInfo(final ApprovalStepMetadata metadata) {
            this.metadataId = metadata.getMetadataId();
            this.instruction = metadata.getInstruction();
            this.options = metadata.getOptions();
            this.optionsType = metadata.getOptionsType();
            this.optionValue = metadata.getOptionValue();
            this.note = metadata.getOptionNote();            
        }
        public int getMetadataId() { return metadataId; }
        public String getInstruction() { return instruction; }
        public int getOptionsType() { return optionsType; }
        public List<String> getOptions() { return options; }
        public String getOptionValue() { return optionValue; }
        public void setOptionValue(String value) { optionValue=value; }
        public List<String> getOptionValueList() { return optionValueList; }
        public void setOptionValueList(List<String> value) { optionValueList=value; }
        public String getNote() { return note; }
        public void setNote(String note) { this.note=note; }

        
    }
    
    private static final long serialVersionUID = 1940920496104779323L;
    private static final Logger log = Logger.getLogger(ApproveActionManagedBean.class);
    
	private final EjbLocalHelper ejb = new EjbLocalHelper();
	private String comment = "";
	private ApprovalDataVOView approveRequestData = new ApprovalDataVOView();      
	private HashMap<Integer, String> statustext = null;
	private ApprovalStep currentApprovalStep = null;
	private ListDataModel<MetadataGuiInfo> metadataList = null;
	private ListDataModel<MetadataGuiInfo> previousMetadataList = null;

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

    public boolean getExistCurrentApprovalStep() {
        if(currentApprovalStep==null) {
            getMetadataList();
        }
        return currentApprovalStep!=null;
    }
    
    public boolean getExistPreviousMetadata() {
        if(previousMetadataList==null) {
            getMetadataList();
        }
        if(previousMetadataList == null) {
            //Handles approvals created prior to 6.6.0
            return false;
        }
        return previousMetadataList.getRowCount() > 0;
    }
    
    
    public ListDataModel<MetadataGuiInfo> getMetadataList() {
        if(metadataList==null) {
            if(currentApprovalStep==null) {
                currentApprovalStep = getApproveRequestData().getApprovalRequest().getNextUnhandledApprovalStepByAdmin(getAdmin());
            }
            if(currentApprovalStep==null) {
                addErrorMessage("AUTHORIZATIONDENIED");
                return null;
            }
            
            ArrayList<MetadataGuiInfo> previousMdGuis = new ArrayList<MetadataGuiInfo>();
            if(currentApprovalStep.canSeePreviousSteps()) {
                final List<ApprovalStep> approvedSteps = getApproveRequestData().getApprovalRequest().getApprovedApprovalSteps();
                for(ApprovalStep previousStep : approvedSteps) {
                    for(ApprovalStepMetadata md : previousStep.getMetadata()) {
                        previousMdGuis.add(new MetadataGuiInfo(md));
                    }
                }
            }
            previousMetadataList = new ListDataModel<MetadataGuiInfo>(previousMdGuis);
            
            ArrayList<MetadataGuiInfo> currentMdGuis = new ArrayList<MetadataGuiInfo>();
            for(ApprovalStepMetadata md : currentApprovalStep.getMetadata()) {
                currentMdGuis.add(new MetadataGuiInfo(md));
            }
            metadataList = new ListDataModel<MetadataGuiInfo>(currentMdGuis);
            
        }
        return metadataList;
    }
    
    public ListDataModel<MetadataGuiInfo> getPreviousMetadataList() {
        if(previousMetadataList==null) {
            getMetadataList();
        }
        return previousMetadataList;
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
        
        final boolean isNrOfApprovalProfile = getApproveRequestData().getApprovalRequest().getApprovalProfile().getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals;
        ApprovalStep step = getApprovalStep();

        if((step==null) && (!isNrOfApprovalProfile)) {
            addErrorMessage("No Approval Steps were found");
        } else {
            final Approval approval = new Approval(comment);
            try {
                final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
                ejb.getApprovalSession().reject(admin,  approveRequestData.getApprovalId(), approval, step, isNrOfApprovalProfile);
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
        }
        return "approveaction";
    }
    
    private ApprovalStep getApprovalStep() {
        if(getApproveRequestData().getApprovalRequest().getApprovalProfile().getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
            return null;
        }
        
        ApprovalRequest approvalRequest = getApproveRequestData().getApprovalRequest();
        if(currentApprovalStep!=null) {
            for(MetadataGuiInfo mdGui : metadataList) {
                String metadataOptionsValue = "";
                if(mdGui.getOptionsType()==ApprovalStepMetadata.METADATATYPE_CHECKBOX) {
                    List<String> data = mdGui.getOptionValueList();
                    for(String p : data) {
                        metadataOptionsValue += p + "; " ;
                    }
                    metadataOptionsValue = metadataOptionsValue.substring(0, metadataOptionsValue.length()-3);
                } else {
                    metadataOptionsValue = mdGui.getOptionValue();
                }
                currentApprovalStep.updateOneMetadataValue(mdGui.getMetadataId(), metadataOptionsValue, mdGui.getNote());
            }
            approvalRequest.updateApprovalStepMetadata(currentApprovalStep.getStepId(), currentApprovalStep.getMetadata());
            return approvalRequest.getApprovalStep(currentApprovalStep.getStepId());
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
