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
import java.util.Date;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.TimeMatch;

/**
 * Managed bean in the actionapprovallist page.
 * 
 * @version $Id$
 */
public class ListApproveActionManagedBean extends BaseManagedBean {

	private static final long serialVersionUID = 1L;
	public static int QUERY_MAX_NUM_ROWS = 300;
	private static String TIME_5MIN = Integer.toString(5 * 60 * 1000);
	private static String TIME_30MIN = Integer.toString(30 * 60 * 1000);
	private static String TIME_8HOURS = Integer.toString(8 * 60 * 60 * 1000);
	private static String ALL_STATUSES = Integer.toString(-9);
	private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
	private List<SelectItem> availableStatus;
	private String selectedStatus;	
	private List<SelectItem> availableTimeSpans;
	private String selectedTimeSpan;
	
	private ApprovalDataVOViewList listData;

	public ListApproveActionManagedBean() {		      			 			 	 	
		setSelectedStatus("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
		setSelectedTimeSpan(TIME_30MIN);
		list();
	}
	
	public List<SelectItem> getAvailableStatus() {
		if(availableStatus == null){
			  availableStatus = new ArrayList<SelectItem>();
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,getEjbcaWebBean().getText("WAITING", true),""));	 
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXPIRED,getEjbcaWebBean().getText("EXPIRED", true),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED,getEjbcaWebBean().getText("EXPIREDANDNOTIFIED", true),""));	  
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTED,getEjbcaWebBean().getText("EXECUTED", true),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTIONFAILED,getEjbcaWebBean().getText("EXECUTIONFAILED", true),""));
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_EXECUTIONDENIED,getEjbcaWebBean().getText("EXECUTIONDENIED", true),""));			  
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_APPROVED,getEjbcaWebBean().getText("APPROVED", true),""));	
			  availableStatus.add(new SelectItem("" + ApprovalDataVO.STATUS_REJECTED,getEjbcaWebBean().getText("REJECTED", true),""));
			  availableStatus.add(new SelectItem(ALL_STATUSES, getEjbcaWebBean().getText("ALL", true),""));			
		}
		return availableStatus;
	}

	public void setAvailableStatus(List<SelectItem> availableStatus) {
		this.availableStatus = availableStatus;
	}

	public List<SelectItem> getAvailableTimeSpans() {
        if (availableTimeSpans == null) {
            availableTimeSpans = new ArrayList<SelectItem>();
            availableTimeSpans.add(new SelectItem(TIME_5MIN, "5 " + getEjbcaWebBean().getText("MINUTES", true), ""));
            availableTimeSpans.add(new SelectItem(TIME_30MIN, "30 " + getEjbcaWebBean().getText("MINUTES", true), ""));
            availableTimeSpans.add(new SelectItem(TIME_8HOURS, "8 " + getEjbcaWebBean().getText("HOURS", true), ""));
            availableTimeSpans.add(new SelectItem("0", getEjbcaWebBean().getText("EVER", true), ""));
        }
		return availableTimeSpans;
	}

	public void setAvailableTimeSpans(List<SelectItem> availableTimeSpans) {
		this.availableTimeSpans = availableTimeSpans;
	}

	public String list() {
		Query query = new Query(Query.TYPE_APPROVALQUERY);
		if(selectedStatus.equals(ALL_STATUSES)){			
			query.add(getStartDate(), new Date());			
		}else if(selectedStatus.equals(Integer.toString(ApprovalDataVO.STATUS_EXPIRED))) {
		    //Expired requests will be set as Waiting in the database. 
		    query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL), Query.CONNECTOR_AND);
		    query.add(TimeMatch.MATCH_WITH_EXPIRETIME, null, new Date(), Query.CONNECTOR_AND);
            query.add(getStartDate(), new Date());
		}else{	
			query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, selectedStatus, Query.CONNECTOR_AND);
			query.add(getStartDate(), new Date());
		}
        List<ApprovalDataVO> result = new ArrayList<ApprovalDataVO>();
		try {
            RAAuthorization raAuthorization = new RAAuthorization(EjbcaJSFHelper.getBean().getAdmin(), ejbLocalHelper.getGlobalConfigurationSession(),
            		ejbLocalHelper.getAuthorizationSession(), ejbLocalHelper.getCaSession(), ejbLocalHelper.getEndEntityProfileSession());
			result = ejbLocalHelper.getApprovalSession().query(query, 0, QUERY_MAX_NUM_ROWS, 
			        raAuthorization.getCAAuthorizationString(), raAuthorization.getEndEntityProfileAuthorizationString(AccessRulesConstants.APPROVE_END_ENTITY));
			if(result.size() == QUERY_MAX_NUM_ROWS){
				String messagestring = getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS1", true) + " " + QUERY_MAX_NUM_ROWS + " " + getEjbcaWebBean().getText("MAXAPPROVALQUERYROWS2", true);
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
	
	/** @return true if approval data is sorted by request date*/
	public boolean isSortedByRequestDate() {
	    //ApprovalDataVOViewList.sort treats null (initial value on page load) as requestDate
	    return getSort() == null || getSort().equals("requestDate");
	}

   /** @return true if approval data is sorted by approve action name*/
	public boolean isSortedByApproveActionName() {
	    return getSort() != null && getSort().equals("approveActionName");
	}
	
    /** @return true if approval data is sorted by requesting administrator*/
	public boolean isSortedByRequestUsername() {
	    return getSort() != null && getSort().equals("requestUsername");
	}
	
    /** @return true if approval data is sorted by request status*/	
	public boolean isSortedByStatus() {
	    return getSort() != null && getSort().equals("status");
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
			return "Row0";
		}
		return "Row0, Row1";
	}

	public List<ApprovalDataVOView> getListData() {
		return listData.getData();
	}

    public String getSort() {
        return listData.getSort();
    }

    public void setSort(String sort) {
    	listData.setSort(sort);
    }

    public boolean isAscending() {
        return listData.isAscending();
    }

    public void setAscending(boolean ascending) {
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
