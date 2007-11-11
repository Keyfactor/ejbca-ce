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
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ra.UserDataVO;
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
 * @version: $Id: CertificateExpirationNotifierWorker.java,v 1.7 2007-11-11 07:55:48 anatom Exp $
 */
public class CertificateExpirationNotifierWorker extends EmailSendingWorker {

	private static final Logger log = Logger.getLogger(CertificateExpirationNotifierWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

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
								String msg = intres.getLocalizedMessage("services.errorworker.errornoemail", username);
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
	/** Method that must be implemented by all subclasses to EmailSendingWorker, used to update status of 
	 * a certificate, user, or similar
	 * @param pk primary key of object to update
	 * @param status status to update to 
	 */
	protected void updateStatus(String pk, int status) {
		Connection con = null;
		PreparedStatement updateStatus = null;
		try{
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			updateStatus = con.prepareStatement("UPDATE CertificateData SET status=? WHERE fingerprint=?");
			updateStatus.setInt(1, status);
			updateStatus.setString(2, pk);
			updateStatus.execute();
		} catch (Exception e) {
			log.error("Error updating certificate status: ", e);
		} finally {
			JDBCUtil.close(con, updateStatus, null);
		}
	}

}
