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

import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UserNotificationParamGen;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;
import org.ejbca.util.JDBCUtil;

/**
 * Makes queries about which certificates that is about to expire in a given
 * number of days and creates an notification sent to either the end user or the
 * administrator.
 * 
 * @author Philip Vendil, Tomas Gustavsson
 * 
 * @version: $Id$
 */
public class CertificateExpirationNotifierWorker extends EmailSendingWorker {

    private static final Logger log = Logger.getLogger(CertificateExpirationNotifierWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Worker that makes a query to the Certificate Store about expiring
     * certificates.
     * 
     * @see org.ejbca.core.model.services.IWorker#work()
     */
    public void work() throws ServiceExecutionFailedException {
        log.trace(">CertificateExpirationNotifierWorker.work started");

        ArrayList userEmailQueue = new ArrayList();
        ArrayList adminEmailQueue = new ArrayList();

        // Build Query
        String cASelectString = "";
        Collection<Integer> ids = getCAIdsToCheck(false);
        if (ids.size() > 0) {
            Iterator<Integer> iter = ids.iterator();
            while (iter.hasNext()) {
                Integer caid = iter.next();
                CAInfo caInfo = getCAAdminSession().getCAInfo(getAdmin(), caid);
                if (caInfo == null) {
                    String msg = intres.getLocalizedMessage("services.errorworker.errornoca", caid, null);
                    log.info(msg);
                    continue;
                }
                String cadn = caInfo.getSubjectDN();
                if (cASelectString.equals("")) {
                    cASelectString = "issuerDN='" + cadn + "' ";
                } else {
                    cASelectString += " OR issuerDN='" + cadn + "' ";
                }
            }

            /*
             * Algorithm:
             * 
             * Inputs: CertificateData.status Which either is ACTIVE or
             * NOTIFIEDABOUTEXPIRATION in order to be candidates for
             * notifications.
             * 
             * nextRunTimestamp Tells when the next service run will be
             * 
             * currRunTimestamp Tells when the service should run (usually "now"
             * but there may be delayed runs as well if the app-server has been
             * down)
             * 
             * thresHold The configured "threshold"
             * 
             * We want to accomplish two things:
             * 
             * 1. Notify for expirations within the service window 2. Notify
             * _once_ for expirations that occurred before the service window
             * like flagging certificates that have a shorter life-span than the
             * threshold (pathologic test-case...)
             * 
             * The first is checked by:
             * 
             * notify = currRunTimestamp + thresHold <= ExpireDate <
             * nextRunTimestamp + thresHold AND (status = ACTIVE OR status =
             * NOTIFIEDABOUTEXPIRATION)
             * 
             * The second can be checked by:
             * 
             * notify = currRunTimestamp + thresHold > ExpireDate AND status =
             * ACTIVE
             * 
             * In both case status can be set to NOTIFIEDABOUTEXPIRATION
             * 
             * As Tomas pointed out we do not need to flag certificates that
             * have expired already which is a separate test.
             */

            long thresHold = getTimeBeforeExpire();
            long currRunTimestamp = serviceConfiguration.getOldRunTimestamp().getTime();
            long nextRunTimestamp = serviceConfiguration.getNextRunTimestamp().getTime();
            long now = new Date().getTime();

            // Execute Query
            Connection con = null;
            PreparedStatement ps = null;
            ResultSet result = null;
            
            if(!cASelectString.equals("")) {
                try {
                    con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
                    // We can not select the base64 certificate data here, because
                    // it may be a LONG data type which we can't simply select
                    String sqlstr = "SELECT DISTINCT fingerprint, username" + " FROM CertificateData WHERE (" + cASelectString + ") AND " + "(expireDate > " + now
                            + ") AND" + "(expireDate < " + (nextRunTimestamp + thresHold) + ") AND " + "(status = " + SecConst.CERT_ACTIVE + " OR status = "
                            + SecConst.CERT_NOTIFIEDABOUTEXPIRATION + ") AND " + "(expireDate >= " + (currRunTimestamp + thresHold) + " OR " + "status = "
                            + SecConst.CERT_ACTIVE + ")";
                    log.debug("Executing search sql: " + sqlstr);
                    ps = con.prepareStatement(sqlstr);
    
                    result = ps.executeQuery();
    
                    // Certificate store session bean for retrieving the
                    // certificate.
                    int count = 0;
                    while (result.next()) {
                        count++;
                        // For each certificate update status.
                        String fingerprint = result.getString(1);
                        String username = result.getString(2);
                        // String certBase64 = result.getString(2);
                        // Get the certificate through a session bean
                        log.debug("Found a certificate we should notify. Username=" + username + ", fp=" + fingerprint);
                        Certificate cert = getCertificateSession().findCertificateByFingerprint(new Admin(Admin.TYPE_INTERNALUSER), fingerprint);
                        UserDataVO userData = getUserAdminSession().findUser(getAdmin(), username);
                        if (userData != null) {
                            if (isSendToEndUsers()) {
                                if (userData.getEmail() == null || userData.getEmail().trim().equals("")) {
                                    String msg = intres.getLocalizedMessage("services.errorworker.errornoemail", username);
                                    log.info(msg);
                                } else {
                                    // Populate end user message
                                    log.debug("Adding to email queue for user: " + userData.getEmail());
                                    String message = new UserNotificationParamGen(userData, cert).interpolate(getEndUserMessage());
                                    MailActionInfo mailActionInfo = new MailActionInfo(userData.getEmail(), getEndUserSubject(), message);
                                    userEmailQueue.add(new EmailCertData(fingerprint, mailActionInfo));
                                }
                            }
                        } else {
                            log.debug("Trying to send notification to user, but no UserData can be found for user '" + username
                                    + "', will only send to admin if admin notifications are defined.");
                        }
                        if (isSendToAdmins()) {
                            // If we did not have any user for this, we will simply
                            // use empty values for substitution
                            if (userData == null) {
                                userData = new UserDataVO();
                                userData.setUsername(username);
                            }
                            // Populate admin message
                            log.debug("Adding to email queue for admin");
                            String message = new UserNotificationParamGen(userData, cert).interpolate(getAdminMessage());
                            MailActionInfo mailActionInfo = new MailActionInfo(null, getAdminSubject(), message);
                            adminEmailQueue.add(new EmailCertData(fingerprint, mailActionInfo));
                        }
                        if (!isSendToEndUsers() && !isSendToAdmins()) {
                            // a little bit of a kludge to make JUnit testing
                            // feasible...
                            log.debug("nobody to notify for cert with fp:" + fingerprint);
                            updateStatus(fingerprint, SecConst.CERT_NOTIFIEDABOUTEXPIRATION);
                        }
                    }
                    if (count == 0) {
                        log.debug("No certificates found for notification.");
                    }
    
                } catch (Exception fe) {
                   log.error("Error running service work: ", fe);
                    throw new ServiceExecutionFailedException(fe);
                } finally {
                    JDBCUtil.close(con, ps, result);
                }
            }

            if (isSendToEndUsers()) {
                sendEmails(userEmailQueue);
            }
            if (isSendToAdmins()) {
                sendEmails(adminEmailQueue);
            }

        } else {
            log.debug("No CAs to check");
        }
        log.trace("<CertificateExpirationNotifierWorker.work ended");
    }

    /**
     * Method that must be implemented by all subclasses to EmailSendingWorker,
     * used to update status of a certificate, user, or similar
     * 
     * @param pk
     *            primary key of object to update
     * @param status
     *            status to update to
     */
    protected void updateStatus(String pk, int status) {
        Connection con = null;
        PreparedStatement updateStatus = null;
        try {
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
