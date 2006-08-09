package org.ejbca.ui.web.admin.approval;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;

import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/*
 * Created on 2005-jun-20
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

/**
 * Managed bean in the actionapprovallist page.
 * 
 * @author Philip Vendil
 * $id$
 */
public class ListApproveActionSessionBean extends BaseManagedBean{
	//private static final Logger log = Logger.getLogger(ListApproveActionSessionBean.class);
	
	public static int QUERY_MAX_NUM_ROWS = 300;
	
	private List availableStatus;
	private String selectedStatus;	
	
	private List availableTimeSpans;
	private String selectedTimeSpan;
	
	private ApprovalDataVOViewList listData;
	
	private static String TIME_5MIN = "" + 5 * 60 * 1000;
	private static String TIME_30MIN = "" + 30 * 60 * 1000;
	private static String TIME_8HOURS = "" + 8 * 60 * 60 * 1000;
	
	private static String ALL_STATUSES = "" + -9;
	

	public ListApproveActionSessionBean() throws AuthorizationDeniedException{		      			 			 	 	
		
	  setSelectedStatus("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
	  setSelectedTimeSpan(TIME_30MIN);
	  
      list();
	}
	
	public List getAvailableStatus() {
		if(availableStatus == null){
			  availableStatus = new ArrayList();
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,getEjbcaWebBean().getText("WAITING"),""));	 
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXPIRED,getEjbcaWebBean().getText("EXPIRED"),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED,getEjbcaWebBean().getText("EXPIREDANDNOTIFIED"),""));	  
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTED,getEjbcaWebBean().getText("EXECUTED"),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTIONFAILED,getEjbcaWebBean().getText("EXECUTIONFAILED"),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTIONDENIED,getEjbcaWebBean().getText("EXECUTIONDENIED"),""));			  
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_APPROVED,getEjbcaWebBean().getText("APPROVED"),""));	
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_REJECTED,getEjbcaWebBean().getText("REJECTED"),""));
			  availableStatus.add(new SelectItem(ALL_STATUSES,getEjbcaWebBean().getText("ALL"),""));			
		}
		
		
		return availableStatus;
	}
	public void setAvailableStatus(List availableStatus) {
		this.availableStatus = availableStatus;
	}

	
	
	public List getAvailableTimeSpans() {
		if(availableTimeSpans == null){
		  availableTimeSpans = new ArrayList();
		  availableTimeSpans.add(new SelectItem(TIME_5MIN ,"5 " + getEjbcaWebBean().getText("MINUTES"),""));	 
		  availableTimeSpans.add(new SelectItem(TIME_30MIN,"30 " + getEjbcaWebBean().getText("MINUTES"),""));
		  availableTimeSpans.add(new SelectItem(TIME_8HOURS,"8 " + getEjbcaWebBean().getText("HOURS"),""));	
		  availableTimeSpans.add(new SelectItem("0",getEjbcaWebBean().getText("EVER"),""));	
		}
		
		return availableTimeSpans;
	}
	public void setAvailableTimeSpans(List availableTimeSpans) {
		this.availableTimeSpans = availableTimeSpans;
	}

	
	public String list() {
				
		Query query = new Query(Query.TYPE_APPROVALQUERY);
		
		if(selectedStatus.equals(ALL_STATUSES)){			
			query.add(getStartDate(), new Date());			
		}else{
			query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, selectedStatus, Query.CONNECTOR_AND);
			query.add(getStartDate(), new Date());
		}
		
        List result = new ArrayList();
		try {
			result = EjbcaJSFHelper.getBean().getApprovalSession().query(EjbcaJSFHelper.getBean().getAdmin(), query, 0, QUERY_MAX_NUM_ROWS);
			if(result.size() == QUERY_MAX_NUM_ROWS){
				String messagestring = getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS1") + " " + QUERY_MAX_NUM_ROWS + " " + getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS2");
				FacesContext ctx = FacesContext.getCurrentInstance();
				ctx.addMessage("error", new FacesMessage(FacesMessage.SEVERITY_ERROR,messagestring,messagestring));
			}
		} catch (IllegalQueryException e) {
           addErrorMessage("INVALIDQUERY");
		} catch (AuthorizationDeniedException e) {
			addErrorMessage("AUTHORIZATIONDENIED");
		}
		
		listData = new ApprovalDataVOViewList(result);

		
		return null;		
	}
	
	/**
	 * Help method to list.
	 */
	private Date getStartDate(){
		if(Integer.parseInt(selectedTimeSpan) == 0){
			return new Date(0);
		}
		
		return new Date(new Date().getTime() - Integer.parseInt(selectedTimeSpan));
	}
	
	public String getRowClasses(){		
		if(listData.size() == 0){
			return "";
		}
		if(listData.size() == 1){
			return "jsfrow1";
		}
		
		return "jsfrow1, jsfrow2";
	}

	public List getListData() {
		
		return listData.getData();
	}
	

    public String getSort()
    {
        return listData.getSort();
    }

    public void setSort(String sort)
    {
    	listData.setSort(sort);
    }

    public boolean isAscending()
    {
        return listData.isAscending();
    }

    public void setAscending(boolean ascending)
    {
        listData.setAscending(ascending);
    }

	public String getSelectedStatus() {
		return selectedStatus;
	}

	public void setSelectedStatus(String selectedStatus) {
		this.selectedStatus = selectedStatus;
	}

	public String getSelectedTimeSpan() {
		return selectedTimeSpan;
	}

	public void setSelectedTimeSpan(String selectedTimeSpan) {
		this.selectedTimeSpan = selectedTimeSpan;
	}
	


	
}
