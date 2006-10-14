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
package org.ejbca.core.model.services.workers;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Email Notifier Worker
 * 
 * Makes queries about which emails that is about to expire in a given number of days
 * and creates an notification sent to either the end user or the administrator.
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class CertificateExpirationNotifierWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(CertificateExpirationNotifierWorker.class);

	/** Should be a ';' separated string of CANames. */
	public static final String PROP_CANAMESTOCHECK     = "worker.emailexpiration.canamestocheck";
	
	/** The time in 'timeunit' remaining of a certificate before sending a notification */
	public static final String PROP_TIMEBEFOREEXPIRING = "worker.emailexpiration.timebeforeexpiring";
	
	/** Unit in days, hours or seconds */
	public static final String PROP_TIMEUNIT           = "worker.emailexpiration.timeunit";
	
	/** Boolean indicating if a notification should be sent to the end user of the certificate */
	public static final String PROP_SENDTOENDUSERS     = "worker.emailexpiration.sendtoendusers";
	
	/** Boolean indicating if a nofification should be sent to the administartors */ 
	public static final String PROP_SENDTOADMINS       = "worker.emailexpiration.sendtoadmins";
	
	/** The subject to use in the end user notification */
	public static final String PROP_USERSUBJECT        = "worker.emailexpiration.usersubject";
	
	/** The message to use in the end user notification. Subsutution varibles are possible in
	 * the same way as for regular notifications.*/
	public static final String PROP_USERMESSAGE        = "worker.emailexpiration.usermessage";
	
	/** The subject to use in the admin notification */
	public static final String PROP_ADMINSUBJECT       = "worker.emailexpiration.adminsubject";
	
	/** The message to use in the adminr notification. Subsutution varibles are possible in
	 * the same way as for regular notifications.*/
	public static final String PROP_ADMINMESSAGE       = "worker.emailexpiration.adminmessage";		
	
	
	public static final String UNIT_SECONDS = "SECONDS";
	public static final String UNIT_MINUTES = "MINUTES";
	public static final String UNIT_HOURS = "HOURS";
	public static final String UNIT_DAYS = "DAYS";
	
	public static final int UNITVAL_SECONDS = 1;
	public static final int UNITVAL_MINUTES = 60;
	public static final int UNITVAL_HOURS = 3600;
	public static final int UNITVAL_DAYS = 86400;

	public static final String[] AVAILABLE_UNITS = {UNIT_SECONDS, UNIT_MINUTES, UNIT_HOURS, UNIT_DAYS};
	public static final int[] AVAILABLE_UNITSVALUES = {UNITVAL_SECONDS, UNITVAL_MINUTES, UNITVAL_HOURS, UNITVAL_DAYS};
	
	private transient Collection cANamesToCheck = null;
	private transient long timeBeforeExpire = -1;
	private transient String endUserSubject = null;
	private transient String adminSubject = null;
	private transient String endUserMessage = null;
	private transient String adminMessage = null;
	
	/**
	 * Worker that makes a query to the Certificate Store about
	 * expiring certificates.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.debug(">CertificateExpirationNotifierWorker.work started");
		//TODO
		
		log.debug("<CertificateExpirationNotifierWorker.work ended");
	}
	
	private Collection getCANamesToCheck(){
		if(cANamesToCheck == null){
			cANamesToCheck = new ArrayList();
			String[] canames = properties.getProperty(PROP_CANAMESTOCHECK).split(";");
			for(int i=0;i<canames.length;i++ ){
				cANamesToCheck.add(canames[i]);
			}
		}
		return cANamesToCheck;
	}
	
	private long getTimeBeforeExpire() throws ServiceExecutionFailedException{
		if(timeBeforeExpire == -1){
			String unit = properties.getProperty(PROP_TIMEUNIT);
			if(unit == null){				
				throw new ServiceExecutionFailedException("Error: Email Expire Notification Worker " + serviceName + " is missconfigured, check unit value");
			}
			int unitval = 0;
			for(int i=0;i<AVAILABLE_UNITS.length;i++){
				if(AVAILABLE_UNITS[i].equalsIgnoreCase(unit)){
					unitval = AVAILABLE_UNITSVALUES[i];
					break;
				}
			}
			if(unitval == 0){				
				throw new ServiceExecutionFailedException("Error: Email Expire Notification Worker " + serviceName + " is missconfigured, check UNIT value");
			}
						
		    String value =  properties.getProperty(PROP_TIMEBEFOREEXPIRING);
		    int intvalue = 0;
		    try{
		      intvalue = Integer.parseInt(value);
		    }catch(NumberFormatException e){
		    	throw new ServiceExecutionFailedException("Error: Email Expire Notification Worker " + serviceName + " is missconfigured, check VALUE value");
		    }
			
			if(intvalue == 0){
				throw new ServiceExecutionFailedException("Error: Email Expire Notification Worker " + serviceName + " is missconfigured, check VALUE value");
			}
			timeBeforeExpire = intvalue * unitval;			
		}

		return timeBeforeExpire;
	}

	private String getAdminMessage() {
		if(adminMessage == null){
			adminMessage =  properties.getProperty(PROP_ADMINMESSAGE,"No Message Configured");
		}		
		return adminMessage;
	}

	private String getAdminSubject() {
		if(adminSubject == null){
			adminSubject =  properties.getProperty(PROP_ADMINSUBJECT,"No Subject Configured");
		}
		
		return adminSubject;
	}

	private String getEndUserMessage() {
		if(endUserMessage == null){
			endUserMessage =  properties.getProperty(PROP_USERMESSAGE,"No Message Configured");
		}
		
		return endUserMessage;
	}

	private String getEndUserSubject() {
		if(endUserSubject == null){
			endUserSubject =  properties.getProperty(PROP_USERSUBJECT,"No Subject Configured");
		}
		
		return endUserSubject;
	}

	private boolean isSendToAdmins() {
		return properties.getProperty(PROP_SENDTOADMINS,"FALSE").equalsIgnoreCase("TRUE");
	}

	private boolean isSendToEndUsers() {
		return properties.getProperty(PROP_SENDTOENDUSERS,"FALSE").equalsIgnoreCase("TRUE");
	}
	


}
