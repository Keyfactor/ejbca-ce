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
package org.ejbca.ui.web.admin.services;

import java.util.ArrayList;
import java.util.List;

import javax.faces.model.SelectItem;

import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Class used to manage the listservices.jsp page
 * Contains and manages the available services
 * 
 * @author Philip Vendil 2006 sep 29
 *
 * @version $Id: ListServicesManagedBean.java,v 1.1 2006-10-01 17:46:48 herrvendil Exp $
 */
public class ListServicesManagedBean extends BaseManagedBean {
	


	private String selectedServiceName;
	
	private String newServiceName = "";

	private List availableServices = new ArrayList();
	
	public ListServicesManagedBean(){
		availableServices.add(new SelectItem("Test Service 1","Test Service 1"));

	}

	public String getSelectedServiceName() {
		return selectedServiceName;
	}

	public void setSelectedServiceName(String string) {
		selectedServiceName = string;
	}

	public List getAvailableServices() {
		if(availableServices == null){
			availableServices = new ArrayList();
			availableServices.add(new SelectItem("" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,"WAITING",""));	 
			availableServices.add(new SelectItem("" + ApprovalDataVO.STATUS_EXPIRED,"EXPIRED",""));
			
		}
		return availableServices;
	}

	public void setAvailableServices(ArrayList list) {
		availableServices = list;
	}
	
	public String editService(){

		
		System.out.println("editService() pressed : selected " + selectedServiceName );
		
		newServiceName = "";
		return "editservice";
	}
	
	public String deleteService(){
		// todo delete
		System.out.println("deleteService() pressed : selected " + selectedServiceName );
		
		newServiceName = "";
		return "listservices";
	}
	
	public String renameService(){
		// todo delete
		System.out.println("renameService() pressed : selected " + selectedServiceName + ", new " +this.newServiceName );
		
		newServiceName = "";
		return "listservices";
	}
	
	public String addService(){
		// todo delete
		System.out.println("addService() pressed : selected " + this.newServiceName );
		
		newServiceName = "";
		return "editservice";
	}
	
	public String cloneService(){
		// todo clone
		System.out.println("cloneService() pressed : selected " + selectedServiceName + ", new " +this.newServiceName );
		
		newServiceName = "";
		return "listservices";
	}

	/**
	 * @return the newServiceName
	 */
	public String getNewServiceName() {
		return newServiceName;
	}

	/**
	 * @param newServiceName the newServiceName to set
	 */
	public void setNewServiceName(String newServiceName) {
		this.newServiceName = newServiceName;
	}



}
