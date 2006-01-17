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
 
package org.ejbca.core.model.ra;

import java.text.DateFormat;
import java.util.Date;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ra.raadmin.DNFieldExtractor;



/**
 * This class is used to create notification messages
 *
 * @version $Id: NotificationCreator.java,v 1.1 2006-01-17 20:28:07 anatom Exp $
 */
public class NotificationCreator {
    private static final Logger log = Logger.getLogger(NotificationCreator.class);
    /**
     * Availabe vairables used to replace text in a message or printlayout
     * Variable text are case-insensitive.
     */
    private static final Pattern USERNAME = Pattern.compile("\\$USERNAME", Pattern.CASE_INSENSITIVE);
    private static final Pattern PASSWORD = Pattern.compile("\\$PASSWORD", Pattern.CASE_INSENSITIVE);
    private static final Pattern CN = Pattern.compile("\\$CN", Pattern.CASE_INSENSITIVE);
    private static final Pattern O = Pattern.compile("\\$O", Pattern.CASE_INSENSITIVE);
    private static final Pattern OU = Pattern.compile("\\$OU", Pattern.CASE_INSENSITIVE);
    private static final Pattern C = Pattern.compile("\\$C", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATE = Pattern.compile("\\$DATE", Pattern.CASE_INSENSITIVE);
    private static final Pattern NEWLINE = Pattern.compile("\\$NL", Pattern.CASE_INSENSITIVE);



    /**
     * Creates a notification creator.
     *
     * @param sender is the address of the sender sending the message.
     * @param subject is the string to be used as subject of notification message
     * @param message is the actual message sent in the email. Should contain the supported
     *        variables.
     */
    public NotificationCreator(String sender, String subject, String message) {
        this.sender = sender;
        this.subject = subject;
        this.message = message;
    }

    /**
     * Returns the Sender email-address of the notificaton
     *
     * @return email address of sender of notification, configured in end entity profiles.
     */
    public String getSender() {
        return sender;
    }

    /**
     * Returns the subject of the notification, observe noting is replaced when calling this function.
     *
     * @return email address of subject of notification, configured in end entity profiles.
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Returns the message with userspecific data replaced.
     *
     *
     * @return A processed notification message.
     *     
     */
    public String getMessage(String username, String password, String dn, String subjectaltname,
        String email) throws Exception {
        String returnval = message;
        DNFieldExtractor dnfields = new DNFieldExtractor(dn, DNFieldExtractor.TYPE_SUBJECTDN);

        // DNFieldExtractor subaltnamefields = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTALTNAME);
        String currentdate = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                                       .format(new Date());
        String newline = System.getProperty("line.separator");

        try {            
            returnval = USERNAME.matcher(returnval).replaceAll(username);
            returnval = PASSWORD.matcher(returnval).replaceAll(password);
            returnval = CN.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.CN, 0));
            returnval = OU.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.OU, 0));
            returnval = O.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.O, 0));
            returnval = C.matcher(returnval).replaceAll(dnfields.getField(DNFieldExtractor.C, 0));
            returnval = DATE.matcher(returnval).replaceAll(currentdate);
            returnval = NEWLINE.matcher(returnval).replaceAll(newline);
        } catch (IllegalArgumentException e) {
            log.error("Error creating message for username: "+username+", password: "+password+", dn: "+dn+", altname: "+subjectaltname+", email: "+email);
            throw e;
        }

        return returnval;
    }

    // Private Variables
    private String sender;
    private String subject;
    private String message;
}
