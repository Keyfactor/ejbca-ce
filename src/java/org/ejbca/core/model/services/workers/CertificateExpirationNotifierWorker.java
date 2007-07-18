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

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.NotificationParamGen;

/**
 * Email Notifier Worker
 * 
 * Makes queries about which emails that is about to expire in a given number of days
 * and creates an notification sent to either the end user or the administrator.
 * 
 * @author Philip Vendil
 *
 * @version: $Id: CertificateExpirationNotifierWorker.java,v 1.6 2007-07-18 13:58:55 anatom Exp $
 */
public class CertificateExpirationNotifierWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(CertificateExpirationNotifierWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

	/** Should be a ';' separated string of CANames. */
	public static final String PROP_CAIDSTOCHECK     = "worker.emailexpiration.caidstocheck";
	
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
	
	private transient Collection cAIdsToCheck = null;
	private transient long timeBeforeExpire = -1;
	private transient String endUserSubject = null;
	private transient String adminSubject = null;
	private transient String endUserMessage = null;
	private transient String adminMessage = null;
	
	private class EmailCertData{
		
		private String fingerPrint = null;
		private MailActionInfo actionInfo = null;
		
		public EmailCertData(String fingerPrint, MailActionInfo actionInfo) {
			super();
			this.fingerPrint = fingerPrint;
			this.actionInfo = actionInfo;
		}

		public String getFingerPrint() {
			return fingerPrint;
		}

		public MailActionInfo getActionInfo() {
			return actionInfo;
		}
		
	}
	
	/**
	 * Worker that makes a query to the Certificate Store about
	 * expiring certificates.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.debug(">CertificateExpirationNotifierWorker.work started");
		
		ArrayList userEmailQueue = new ArrayList();
		ArrayList adminEmailQueue = new ArrayList();
		
		// Build Query
		String cASelectString = "";
		if(getCAIdsToCheck().size() >0){
			Iterator iter = getCAIdsToCheck().iterator();
			while(iter.hasNext()){
				String caid = (String) iter.next();
				String cadn = getCAAdminSession().getCAInfo(getAdmin(), Integer.parseInt(caid)).getSubjectDN();
				if(cASelectString.equals("")){
					cASelectString = "issuerDN='" + cadn +"' ";
				}else{
					cASelectString += " OR issuerDN='" + cadn +"' ";
				}
			}

			String checkDate = "expireDate <= " + ((new Date()).getTime() + getTimeBeforeExpire());			
			String statuses = "status=" +CertificateDataBean.CERT_ACTIVE;

			// Execute Query
			Connection con = null;
			PreparedStatement ps = null;
			PreparedStatement updateStatus = null;
			ResultSet result = null;

			try{		
				con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
				ps = con.prepareStatement("SELECT DISTINCT fingerprint, base64Cert, username"
						+ " FROM CertificateData WHERE ("
						+ cASelectString + ") AND (" 
						+ checkDate + ") AND (" 
						+ statuses + ")");            
				
				result = ps.executeQuery();

				while(result.next()){
					// For each certificate update status.
					String fingerprint = result.getString(1);
					String certBase64 = result.getString(2);
					String username = result.getString(3);
					X509Certificate cert = CertTools.getCertfromByteArray(Base64.decode(certBase64.getBytes()));					                  
					
					UserDataVO userData = getUserAdminSession().findUser(getAdmin(), username);
					if(userData != null){
						String userDN = userData.getDN();

						if(isSendToEndUsers()){
							NotificationParamGen paramGen = new NotificationParamGen(userDN,cert);
							if(userData.getEmail() == null || userData.getEmail().trim().equals("")){
								String msg = intres.getLocalizedMessage("services.certexpireworker.errornoemail", username);
								log.info(msg);
							}else{
								// Populate end user message            	    	        		    
								String message = NotificationParamGen.interpolate(paramGen.getParams(), getEndUserMessage());
								MailActionInfo mailActionInfo = new MailActionInfo(userData.getEmail(),getEndUserSubject(), message);
								userEmailQueue.add(new EmailCertData(fingerprint,mailActionInfo));
							}					  
						}
					}
					if(isSendToAdmins()){
						// Populate admin message        		    
						NotificationParamGen paramGen = new NotificationParamGen(cert.getSubjectDN().toString(),cert);
						String message = NotificationParamGen.interpolate(paramGen.getParams(), getAdminMessage());
						MailActionInfo mailActionInfo = new MailActionInfo(null,getAdminSubject(), message);						
						adminEmailQueue.add(new EmailCertData(fingerprint,mailActionInfo));
					}	
					

				}



			} catch (Exception fe) {
				log.error("Error running service work: ", fe);
				throw new ServiceExecutionFailedException(fe);
			} finally {
				if(updateStatus != null){
					JDBCUtil.close(updateStatus);
				}
				JDBCUtil.close(con, ps, result);
			}
			
			
			if(isSendToEndUsers()){
				sendEmails(userEmailQueue);
			}
			if(isSendToAdmins()){
                sendEmails(adminEmailQueue);
			}	

		}
		log.debug("<CertificateExpirationNotifierWorker.work ended");
	}
	
	private void sendEmails(ArrayList queue) throws ServiceExecutionFailedException{
		Iterator iter = queue.iterator();
		while(iter.hasNext()){			
			Connection con = null;
			PreparedStatement updateStatus = null;
			try{
				con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
				EmailCertData next = (EmailCertData) iter.next();								
				getAction().performAction(next.getActionInfo());
				updateStatus = con.prepareStatement("UPDATE CertificateData SET status=" + CertificateDataBean.CERT_NOTIFIEDABOUTEXPIRATION +" WHERE fingerprint='" + next.getFingerPrint() + "'"); 												
				updateStatus.execute();
			} catch (Exception fe) {
				log.error("Error sending emails: ", fe);
				throw new ServiceExecutionFailedException(fe);
			} finally {
				if(updateStatus != null){
					JDBCUtil.close(updateStatus);
				}
				if(con != null){
				  JDBCUtil.close(con);
				}
			}
		}
	}
	
	private Collection getCAIdsToCheck(){
		if(cAIdsToCheck == null){
			cAIdsToCheck = new ArrayList();
			String[] canames = properties.getProperty(PROP_CAIDSTOCHECK).split(";");
			for(int i=0;i<canames.length;i++ ){
				cAIdsToCheck.add(canames[i]);
			}
		}
		return cAIdsToCheck;
	}
	
	private long getTimeBeforeExpire() throws ServiceExecutionFailedException{
		if(timeBeforeExpire == -1){
			String unit = properties.getProperty(PROP_TIMEUNIT);
			if(unit == null){				
				String msg = intres.getLocalizedMessage("services.certexpireworker.errorconfig", serviceName, "UNIT");
				throw new ServiceExecutionFailedException(msg);
			}
			int unitval = 0;
			for(int i=0;i<AVAILABLE_UNITS.length;i++){
				if(AVAILABLE_UNITS[i].equalsIgnoreCase(unit)){
					unitval = AVAILABLE_UNITSVALUES[i];
					break;
				}
			}
			if(unitval == 0){				
				String msg = intres.getLocalizedMessage("services.certexpireworker.errorconfig", serviceName, "UNIT");
				throw new ServiceExecutionFailedException(msg);
			}
						
		    String value =  properties.getProperty(PROP_TIMEBEFOREEXPIRING);
		    int intvalue = 0;
		    try{
		      intvalue = Integer.parseInt(value);
		    }catch(NumberFormatException e){
				String msg = intres.getLocalizedMessage("services.certexpireworker.errorconfig", serviceName, "VALUE");
		    	throw new ServiceExecutionFailedException(msg);
		    }
			
			if(intvalue == 0){
				String msg = intres.getLocalizedMessage("services.certexpireworker.errorconfig", serviceName, "VALUE");
				throw new ServiceExecutionFailedException(msg);
			}
			timeBeforeExpire = intvalue * unitval;			
		}

		return timeBeforeExpire * 1000;
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
