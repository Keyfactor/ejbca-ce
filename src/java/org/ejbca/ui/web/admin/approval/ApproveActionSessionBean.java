package org.ejbca.ui.web.admin.approval;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;


/**
 * Seesion scoped bean for displaying information about an approval request.
 * 
 * @author Philip Vendil
 * 
 *  $Id: ApproveActionSessionBean.java,v 1.1 2006-08-09 07:29:48 herrvendil Exp $
 */
public class ApproveActionSessionBean extends BaseManagedBean {
	private static final Logger log = Logger.getLogger(ApproveActionSessionBean.class);

	private String comment = "";

	public ApproveActionSessionBean() {
		super();		
		
		approveRequestData = new ApprovalDataVOView();         
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
   
   public String approve(){
	   Approval approval = new Approval(comment);
	   try {		   
		   EjbcaJSFHelper.getBean().getApprovalSession().approve(EjbcaJSFHelper.getBean().getAdmin(), approveRequestData.getApprovalId(), approval);
		   updateApprovalRequestData(approveRequestData.getApproveActionDataVO().getId());
	   } catch (ApprovalRequestExpiredException e) {
		   addErrorMessage("APPROVALREQUESTEXPIRED");
	   } catch (ApprovalRequestExecutionException e) {
		   addErrorMessage("ERROREXECUTINGACTION");
	   } catch (AuthorizationDeniedException e) {
		   addErrorMessage("AUTHORIZATIONDENIED");
	   } catch (ApprovalException e) {
		   addErrorMessage("ERRORHAPPENDWHENAPPROVING");
	   } catch (AdminAlreadyApprovedRequestException e) {
		   addErrorMessage("ADMINALREADYPROCESSED");
	   }

	   return "approveaction";
   }
   
   public String reject(){
	   Approval approval = new Approval(comment);

		try {
			EjbcaJSFHelper.getBean().getApprovalSession().reject(EjbcaJSFHelper.getBean().getAdmin(),  approveRequestData.getApprovalId(), approval);
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
		result = EjbcaJSFHelper.getBean().getApprovalSession().query( EjbcaJSFHelper.getBean().getAdmin(), query, 0, 1);
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
