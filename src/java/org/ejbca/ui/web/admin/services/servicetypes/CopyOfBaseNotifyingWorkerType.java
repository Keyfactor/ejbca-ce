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

import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.CertificateExpirationNotifierWorker;
import org.ejbca.core.model.services.workers.EmailSendingWorker;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class managing the view of the Certificate Exiration Notifier Worker
 * 
 * @author Philip Vendil
 *
 */
public class CopyOfBaseNotifyingWorkerType extends WorkerType {

	private Collection compatibleActionTypeNames = new ArrayList();
	private Collection compatibleIntervalTypeNames = new ArrayList();	
	
	
	public static final String DEFAULT_TIMEUNIT = BaseWorker.UNIT_DAYS;
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
	
	private String classpath = null;
	
	
	
	public CopyOfBaseNotifyingWorkerType(String name, String jsp, String classpath){
		super(jsp, name, true);
		this.classpath = classpath;
		
		compatibleActionTypeNames.add(MailActionType.NAME);
		compatibleActionTypeNames.add(NoActionType.NAME);
		
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
		return classpath;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties(ArrayList errorMessages) throws IOException {
		Properties retval = new Properties();
		
		Iterator iter = selectedCANamesToCheck.iterator();		
		String caIdString = "";
		while(iter.hasNext()){
			String cAid = (String) iter.next();
			if(!cAid.trim().equals("")){
			  if(caIdString.equals("")){
				caIdString = cAid;
			  }else{
				caIdString += ";"+cAid;
			  }
			}
		}
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_CAIDSTOCHECK, caIdString);
		
		retval.setProperty(CertificateExpirationNotifierWorker.PROP_TIMEUNIT, timeUnit);
		
		try{
			int value = Integer.parseInt(timeValue);
			if(value < 1){
				throw new NumberFormatException();
			}
		}catch(NumberFormatException e){
			errorMessages.add("TIMEBEFOREEXPIRATIONERROR");
		}
		retval.setProperty(EmailSendingWorker.PROP_TIMEBEFOREEXPIRING, timeValue);
		
		if(useEndUserNotifications){
			retval.setProperty(EmailSendingWorker.PROP_SENDTOENDUSERS, "TRUE");
			retval.setProperty(EmailSendingWorker.PROP_USERSUBJECT,endUserSubject);
			retval.setProperty(EmailSendingWorker.PROP_USERMESSAGE,endUserMessage);
		}else{
			retval.setProperty(EmailSendingWorker.PROP_SENDTOENDUSERS, "FALSE");
			retval.setProperty(EmailSendingWorker.PROP_USERSUBJECT,"");
			retval.setProperty(EmailSendingWorker.PROP_USERMESSAGE,"");
		}
		
		if(useAdminNotifications){
			retval.setProperty(EmailSendingWorker.PROP_SENDTOADMINS, "TRUE");
			retval.setProperty(EmailSendingWorker.PROP_ADMINSUBJECT,adminSubject);
			retval.setProperty(EmailSendingWorker.PROP_ADMINMESSAGE,adminMessage);
		}else{
			retval.setProperty(EmailSendingWorker.PROP_SENDTOADMINS, "FALSE");			
			retval.setProperty(EmailSendingWorker.PROP_ADMINSUBJECT,"");
			retval.setProperty(EmailSendingWorker.PROP_ADMINMESSAGE,"");
		}
		
	
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
		
		
		String[] caIdsToCheck = properties.getProperty(BaseWorker.PROP_CAIDSTOCHECK,"").split(";");
		for(int i=0;i<caIdsToCheck.length;i++){
			selectedCANamesToCheck.add(caIdsToCheck[i]);
		}

		 
		timeUnit = properties.getProperty(BaseWorker.PROP_TIMEUNIT,DEFAULT_TIMEUNIT);
		timeValue = properties.getProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING,DEFAULT_TIMEVALUE);

		useEndUserNotifications = properties.getProperty(EmailSendingWorker.PROP_SENDTOENDUSERS,"").equalsIgnoreCase("TRUE");
		useAdminNotifications = properties.getProperty(EmailSendingWorker.PROP_SENDTOADMINS,"").equalsIgnoreCase("TRUE");
		
       	endUserSubject = properties.getProperty(EmailSendingWorker.PROP_USERSUBJECT,"");
		adminSubject = properties.getProperty(EmailSendingWorker.PROP_ADMINSUBJECT,"");
		endUserMessage = properties.getProperty(EmailSendingWorker.PROP_USERMESSAGE,"");
		adminMessage = properties.getProperty(EmailSendingWorker.PROP_ADMINMESSAGE,"");

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
