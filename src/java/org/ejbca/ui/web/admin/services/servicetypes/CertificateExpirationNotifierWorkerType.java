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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class managing the view of the Certificate Exiration Notifier Worker
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class CertificateExpirationNotifierWorkerType extends WorkerType {

	public static final String NAME = "CERTNOTIFICATIONWORKER";
	
	private Collection compatibleActionTypeNames = new ArrayList();
	private Collection compatibleIntervalTypeNames = new ArrayList();	
	
	
	public static final String DEFAULT_TIMEUNIT = CertificateExpirationNotifierWorker.UNIT_DAYS;
	public static final String DEFAULT_TIMEVALUE = "7";
	
	public static final boolean DEFAULT_USEENDUSERNOTIFICATIONS = false;
	public static final boolean DEFAULT_USEADMINNOTIFICATIONS = false;
	
	
	private List selectedCANamesToCheck = new ArrayList();
	private String timeUnit  = DEFAULT_TIMEUNIT;
	private String timeValue = DEFAULT_TIMEVALUE;
	private boolean useEndUserNotifications = DEFAULT_USEENDUSERNOTIFICATIONS;
	private boolean useAdminNotifications = DEFAULT_USEADMINNOTIFICATIONS;	
	private String endUserSubject = "";
	private String adminSubject = "";
	private String endUserMessage = "";
	private String adminMessage = "";
	
	
	
	public CertificateExpirationNotifierWorkerType(){
		super("certnotificationworker.jsp", NAME, true);
		
		compatibleActionTypeNames.add(MailActionType.NAME);
		
		compatibleIntervalTypeNames.add(PeriodicalIntervalType.NAME);
	}
	/**
	 * 
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleActionTypeNames()
	 */
	public Collection getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleIntervalTypeNames()
	 */
	public Collection getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getClassPath()
	 */
	public String getClassPath() {
		return "org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker";
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties() throws IOException {
		Properties retval = new Properties();
		
		Iterator iter = selectedCANamesToCheck.iterator();
		String caNameString = "";
		while(iter.hasNext()){
			String cAName = (String) iter.next();
			if(caNameString.equals("")){
				caNameString = cAName;
			}else{
				caNameString += ";"+cAName;
			}
		}
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_CANAMESTOCHECK, caNameString);
		
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_TIMEUNIT, timeUnit);
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_TIMEBEFOREEXPIRING, timeValue);
		
		if(useEndUserNotifications){
			retval.setProperty(CertificateExpirationNotifierWorker.PROP_SENDTOENDUSERS, "TRUE");
		}else{
			retval.setProperty(CertificateExpirationNotifierWorker.PROP_SENDTOENDUSERS, "FALSE");
		}
		
		if(useAdminNotifications){
			retval.setProperty(CertificateExpirationNotifierWorker.PROP_SENDTOADMINS, "TRUE");
		}else{
			retval.setProperty(CertificateExpirationNotifierWorker.PROP_SENDTOADMINS, "FALSE");
		}
		
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_USERSUBJECT,endUserSubject);
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_ADMINSUBJECT,adminSubject);
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_USERMESSAGE,endUserMessage);
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_ADMINMESSAGE,adminMessage);
		
	
		return retval;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#isCustom()
	 */
	public boolean isCustom() {
		return false;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {
		selectedCANamesToCheck = new ArrayList();
		
		String[] caNamesToCheck = properties.getProperty(CertificateExpirationNotifierWorker.PROP_CANAMESTOCHECK).split(";");
		for(int i=0;i<caNamesToCheck.length;i++){
			selectedCANamesToCheck.add(caNamesToCheck[i]);
		}
		 
		timeUnit = properties.getProperty(CertificateExpirationNotifierWorker.PROP_TIMEUNIT);
		timeValue = properties.getProperty(CertificateExpirationNotifierWorker.PROP_TIMEBEFOREEXPIRING);

		useEndUserNotifications = properties.getProperty(CertificateExpirationNotifierWorker.PROP_SENDTOENDUSERS).equalsIgnoreCase("TRUE");
		useAdminNotifications = properties.getProperty(CertificateExpirationNotifierWorker.PROP_SENDTOADMINS).equalsIgnoreCase("TRUE");
		
       	endUserSubject = properties.getProperty(CertificateExpirationNotifierWorker.PROP_USERSUBJECT,"");
		adminSubject = properties.getProperty(CertificateExpirationNotifierWorker.PROP_ADMINSUBJECT,"");
		endUserMessage = properties.getProperty(CertificateExpirationNotifierWorker.PROP_USERMESSAGE,"");
		adminMessage = properties.getProperty(CertificateExpirationNotifierWorker.PROP_ADMINMESSAGE,"");

	}
	
	public String getTimeUnit() {
		return timeUnit;
	}

	public void setTimeUnit(String unit) {
		this.timeUnit = unit;
	}
	
	public List getAvailableUnits(){
		ArrayList retval = new ArrayList();
		for(int i = 0 ; i<PeriodicalInterval.AVAILABLE_UNITS.length; i++){
			retval.add(new SelectItem(PeriodicalInterval.AVAILABLE_UNITS[i],(String) EjbcaJSFHelper.getBean().getText().get(PeriodicalInterval.AVAILABLE_UNITS[i])));
		}
		
		return retval;
	}
	public String getAdminMessage() {
		return adminMessage;
	}
	public void setAdminMessage(String adminMessage) {
		this.adminMessage = adminMessage;
	}
	public String getAdminSubject() {
		return adminSubject;
	}
	public void setAdminSubject(String adminSubject) {
		this.adminSubject = adminSubject;
	}
	public String getEndUserMessage() {
		return endUserMessage;
	}
	public void setEndUserMessage(String endUserMessage) {
		this.endUserMessage = endUserMessage;
	}
	public String getEndUserSubject() {
		return endUserSubject;
	}
	public void setEndUserSubject(String endUserSubject) {
		this.endUserSubject = endUserSubject;
	}
	public List getSelectedCANamesToCheck() {
		return selectedCANamesToCheck;
	}
	public void setSelectedCANamesToCheck(List selectedCANamesToCheck) {
		this.selectedCANamesToCheck = selectedCANamesToCheck;
	}
	public String getTimeValue() {
		return timeValue;
	}
	public void setTimeValue(String timeValue) {
		this.timeValue = timeValue;
	}
	public boolean isUseAdminNotifications() {
		return useAdminNotifications;
	}
	public void setUseAdminNotifications(boolean useAdminNotifications) {
		this.useAdminNotifications = useAdminNotifications;
	}
	public boolean isUseEndUserNotifications() {
		return useEndUserNotifications;
	}
	public void setUseEndUserNotifications(boolean useEndUserNotifications) {
		this.useEndUserNotifications = useEndUserNotifications;
	}

}
