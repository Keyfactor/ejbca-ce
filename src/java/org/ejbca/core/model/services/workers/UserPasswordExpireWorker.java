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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UserNotificationParamGen;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;
import org.ejbca.util.JDBCUtil;

/**
 * Worker expiring users password after a configured amount of time.
 * 
 * Makes queries for users with status new, which was not modified in a certain amount of time, and sets
 * the status of these users to generated. Can be used for the following scenario:
 * - A user is generated and given username password to fetch the certificates
 * - If the user does not fetch his certificate within a configured amount of time the user is expired and is not allowed to fetch the certificate any more
 * 
 * @author Tomas Gustavsson based on code by Philip Vendil
 *
 * @version: $Id$
 */
public class UserPasswordExpireWorker extends EmailSendingWorker {

	private static final Logger log = Logger.getLogger(UserPasswordExpireWorker.class);
    /** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();	
	
	private PreparedStatement buildPreparedQueryStatement(Connection con) throws ServiceExecutionFailedException, SQLException {
		// Build Query
		String cASelectString = null;
		Collection caIds = getCAIdsToCheck(false);
		log.debug("Checking for "+caIds.size()+" CAs");
		Iterator iter = caIds.iterator();
		while (iter.hasNext()) {
			iter.next();
			if (cASelectString == null) {
				cASelectString = "cAId=?";
			} else {
				cASelectString += " OR cAId=?";
			}
		}
		StringBuffer str = new StringBuffer();
		str.append("SELECT DISTINCT username FROM UserData WHERE (timeModified <=?) AND (status=?)");
		if (StringUtils.isNotEmpty(cASelectString)) {
			str.append(" AND (").append(cASelectString).append(")");
		}
		if (log.isDebugEnabled()) {
			log.debug("Generated query string: "+str.toString());
		}
		PreparedStatement ps = con.prepareStatement(str.toString());
		ps.setLong(1, ((new Date()).getTime() - getTimeBeforeExpire()));
		ps.setInt(2, UserDataConstants.STATUS_NEW);
		iter = caIds.iterator();	
		int i = 3;
		while (iter.hasNext()) {
			ps.setInt(i++, (Integer)iter.next());
		}
		return ps;
	}
	
	/**
	 * Worker that makes a query to the Certificate Store about
	 * expiring certificates.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
		log.trace(">Worker started");

		ArrayList userEmailQueue = new ArrayList();
		ArrayList adminEmailQueue = new ArrayList();

		// Execute Query
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet result = null;
		try{		
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			ps = buildPreparedQueryStatement(con);

			result = ps.executeQuery();
			while(result.next()){
				// For each user update status.
				String username = result.getString(1);
				if (log.isDebugEnabled()) {
					log.debug("User '"+username+"' has expired and will be set to generated");
				}

				UserDataVO userData = getUserAdminSession().findUser(getAdmin(), username);
				// Update user to set status to generated
				userData.setStatus(UserDataConstants.STATUS_GENERATED);
				userData.setPassword(null);
				getUserAdminSession().changeUser(getAdmin(), userData, false);
				// Create notification emails, if they are configured to be sent
				if(userData != null){
					if(isSendToEndUsers()){
						if(userData.getEmail() == null || userData.getEmail().trim().equals("")){
							String msg = intres.getLocalizedMessage("services.errorworker.errornoemail", username);
							log.info(msg);
						}else{
							// Populate end user message            	    	        		    
							String message = new UserNotificationParamGen(userData).interpolate(getEndUserMessage());
							MailActionInfo mailActionInfo = new MailActionInfo(userData.getEmail(),getEndUserSubject(), message);
							userEmailQueue.add(new EmailCertData(username,mailActionInfo));
						}					  
					}
					if(isSendToAdmins()){
						// Populate admin message        		    
						String message = new UserNotificationParamGen(userData).interpolate(getAdminMessage());
						MailActionInfo mailActionInfo = new MailActionInfo(null,getAdminSubject(), message);						
						adminEmailQueue.add(new EmailCertData(username,mailActionInfo));
					}	
				}
			}
			
		} catch (Exception fe) {
			log.error("Error running service work: ", fe);
			throw new ServiceExecutionFailedException(fe);
		} finally {
			JDBCUtil.close(con, ps, result);
		}

		// Send of the mails
		if(isSendToEndUsers()){
			sendEmails(userEmailQueue);
		}
		if(isSendToAdmins()){
			sendEmails(adminEmailQueue);
		}	

		log.trace("<Worker ended");
	}
	
	/** Method that must be implemented by all subclasses to EmailSendingWorker, used to update status of 
	 * a certificate, user, or similar
	 * @param pk primary key of object to update
	 * @param status status to update to 
	 */
	protected void updateStatus(String pk, int status) {
		// Do nothing
	}

}
