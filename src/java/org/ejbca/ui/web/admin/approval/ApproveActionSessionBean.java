/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
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
 * @author Philip Vendil
 * @version $Id$
 */
public class ApproveActionSessionBean extends BaseManagedBean {
	private static final Logger log = Logger.getLogger(ApproveActionSessionBean.class);

	private String comment = "";

	public ApproveActionSessionBean() {
		super();		
		
		approveRequestData = new ApprovalDataVOView();         
	}


	private  HashMap statustext = null;
    
	public  HashMap getStatusText(){
	    if(statustext == null){
	    	EjbcaWebBean ejbcawebbean = EjbcaJSFHelper.getBean().getEjbcaWebBean();
	    	statustext = new HashMap();
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL), ejbcawebbean.getText("WAITING", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_EXPIRED), ejbcawebbean.getText("EXPIRED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED), ejbcawebbean.getText("EXPIREDANDNOTIFIED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_EXECUTED), ejbcawebbean.getText("EXECUTED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_APPROVED), ejbcawebbean.getText("APPROVED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_REJECTED), ejbcawebbean.getText("REJECTED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_EXECUTIONFAILED), ejbcawebbean.getText("EXECUTIONFAILED", true));
	    	statustext.put(new Integer(ApprovalDataVO.STATUS_EXECUTIONDENIED), ejbcawebbean.getText("EXECUTIONDENIED", true));
	    }
	    return statustext;
	}

	private ApprovalDataVOView approveRequestData;
	
	
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
   

public List getApprovalViews(){
   	  List approvalViews = new ArrayList();
   	 
   	 if(approveRequestData != null && 
   	    approveRequestData.getApproveActionDataVO().getApprovals() != null){   	  	
   	  	Iterator iter =  approveRequestData.getApproveActionDataVO().getApprovals().iterator();
   	  	while(iter.hasNext())
   	  	{
   	  		approvalViews.add(new ApprovalView((Approval) iter.next()));
   	  	}
   	  } 
   	  return approvalViews; 
   }
   
   public boolean isExistsApprovals(){
   	  return approveRequestData.getApproveActionDataVO().getApprovals().size() >0;
   }
   
   public boolean isApprovable(){
   	  if(approveRequestData.getApproveActionDataVO().getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
   	    return true;
   	  }
   	    
   	  return false;
   }
   
   public void setApprobalViews(List list){}
   
   public String approve() {
	   Approval approval = new Approval(comment);
	   try {		   
		   Admin admin = EjbcaJSFHelper.getBean().getAdmin();
		   EjbcaJSFHelper.getBean().getApprovalSession().approve(admin, approveRequestData.getApprovalId(), approval, EjbcaJSFHelper.getBean().getRaAdminSession().loadGlobalConfiguration(admin));
		   updateApprovalRequestData(approveRequestData.getApproveActionDataVO().getId());
	   } catch (ApprovalRequestExpiredException e) {
		   addErrorMessage("APPROVALREQUESTEXPIRED");
	   } catch (ApprovalRequestExecutionException e) {
		   addErrorMessage("ERROREXECUTINGREQUEST");
	   } catch (AuthorizationDeniedException e) {
		   addErrorMessage("AUTHORIZATIONDENIED");
	   } catch (ApprovalException e) {
		   addErrorMessage("ERRORHAPPENDWHENAPPROVING");
	   } catch (AdminAlreadyApprovedRequestException e) {
		   addErrorMessage("ADMINALREADYPROCESSED");
	   } catch (EjbcaException e) {
		   addErrorMessage(e.getErrorCode() + e.getMessage());
	}
	   return "approveaction";
   }
   
   public String reject(){
	   Approval approval = new Approval(comment);
		try {
			Admin admin = EjbcaJSFHelper.getBean().getAdmin();
			EjbcaJSFHelper.getBean().getApprovalSession().reject(admin,  approveRequestData.getApprovalId(), approval, EjbcaJSFHelper.getBean().getRaAdminSession().loadGlobalConfiguration(admin));
			updateApprovalRequestData(approveRequestData.getApproveActionDataVO().getId());
		} catch (ApprovalRequestExpiredException e) {
			addErrorMessage("APPROVALREQUESTEXPIRED");
		} catch (AuthorizationDeniedException e) {
			addErrorMessage("AUTHORIZATIONDENIED");
		} catch (ApprovalException e) {
			addErrorMessage("ERRORHAPPENDWHENAPPROVING");
		} catch (AdminAlreadyApprovedRequestException e) {
			addErrorMessage("ADMINALREADYPROCESSED");
		}

	   return "approveaction";
   }

public void setUniqueId(int uniqueId) {
	log.debug("ApproveActionSessionBean.setApprovalId setting uniqueId : " + uniqueId);
	updateApprovalRequestData(uniqueId);	
}

public void updateApprovalRequestData(int id){
	Query query = new Query(Query.TYPE_APPROVALQUERY);
	query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));
	
	List result;
	try {
        RAAuthorization raAuthorization = new RAAuthorization(EjbcaJSFHelper.getBean().getAdmin(), EjbcaJSFHelper.getBean().getRaAdminSession(), EjbcaJSFHelper.getBean().getAuthorizationSession(), EjbcaJSFHelper.getBean().getCAAdminSession());
		result = EjbcaJSFHelper.getBean().getApprovalSession().query( EjbcaJSFHelper.getBean().getAdmin(), query, 0, 1, raAuthorization.getCAAuthorizationString(), raAuthorization.getEndEntityProfileAuthorizationString());
		if(result.size() > 0){
			this.approveRequestData = new ApprovalDataVOView((ApprovalDataVO) result.get(0));
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
