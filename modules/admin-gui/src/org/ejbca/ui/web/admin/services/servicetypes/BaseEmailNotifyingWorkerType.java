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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.faces.model.SelectItem;

import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.intervals.PeriodicalInterval;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class managing the view of the Certificate Expiration Notifier Worker
 * 
 * @version $Id$
 *
 */
public abstract class BaseEmailNotifyingWorkerType extends BaseWorkerType {

   
    public static final boolean DEFAULT_USEENDUSERNOTIFICATIONS = false;
	public static final boolean DEFAULT_USEADMINNOTIFICATIONS = false;
	
	 private static final long serialVersionUID = -4521088640797284656L;
	
	private String timeUnit  = DEFAULT_TIMEUNIT;
	private String timeValue = DEFAULT_TIMEVALUE;
	private boolean useEndUserNotifications = DEFAULT_USEENDUSERNOTIFICATIONS;
	private boolean useAdminNotifications = DEFAULT_USEADMINNOTIFICATIONS;	
	private String endUserSubject = "";
	private String adminSubject = "";
	private String endUserMessage = "";
	private String adminMessage = "";
	
	public BaseEmailNotifyingWorkerType(String name, String jsp, String classpath){
		super(jsp, name, true, classpath);
		
		addCompatibleActionTypeName(MailActionType.NAME);
		addCompatibleActionTypeName(NoActionType.NAME);
		
		addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
	}
	
	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {
		Properties retval = super.getProperties(errorMessages);
				
		retval.setProperty(BaseWorker.PROP_TIMEUNIT, timeUnit);
		
		try{
			int value = Integer.parseInt(timeValue);
			if(value < 1){
				throw new NumberFormatException();
			}
		}catch(NumberFormatException e){
			errorMessages.add("TIMEBEFOREEXPIRATIONERROR");
		}
		retval.setProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING, timeValue);
		
		if(useEndUserNotifications){
			retval.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "TRUE");
			retval.setProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT,endUserSubject);
			retval.setProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE,endUserMessage);
		}else{
			retval.setProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS, "FALSE");
			retval.setProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT,"");
			retval.setProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE,"");
		}
		
		if(useAdminNotifications){
			retval.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "TRUE");
			retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT,adminSubject);
			retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE,adminMessage);
		}else{
			retval.setProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS, "FALSE");			
			retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT,"");
			retval.setProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE,"");
		}
		
	
		return retval;
	}

	/** Overrides
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {
		super.setProperties(properties);
		 
		timeUnit = properties.getProperty(BaseWorker.PROP_TIMEUNIT,DEFAULT_TIMEUNIT);
		timeValue = properties.getProperty(BaseWorker.PROP_TIMEBEFOREEXPIRING,DEFAULT_TIMEVALUE);

		useEndUserNotifications = properties.getProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS,"").equalsIgnoreCase("TRUE");
		useAdminNotifications = properties.getProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS,"").equalsIgnoreCase("TRUE");
		
       	endUserSubject = properties.getProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT,"");
		adminSubject = properties.getProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT,"");
		endUserMessage = properties.getProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE,"");
		adminMessage = properties.getProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE,"");

	}
	
	public String getTimeUnit() {
		return timeUnit;
	}

	public void setTimeUnit(String unit) {
		this.timeUnit = unit;
	}
	
	public List<SelectItem> getAvailableUnits(){
		ArrayList<SelectItem> retval = new ArrayList<SelectItem>();
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
