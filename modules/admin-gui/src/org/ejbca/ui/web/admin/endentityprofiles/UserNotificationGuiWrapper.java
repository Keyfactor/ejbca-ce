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
package org.ejbca.ui.web.admin.endentityprofiles;

import java.io.Serializable;
import java.util.Collection;

import org.ejbca.core.model.ra.raadmin.UserNotification;

/**
 * GUI wrapper around UserNotification. Needed because JSF cannot access properties
 * in objects that extend from HashMap (because the get() method is used instead of the getters)
 * @version $Id$
 */
public class UserNotificationGuiWrapper implements Serializable {

    private static final long serialVersionUID = 1L;

    private final UserNotification userNotification;

    public UserNotificationGuiWrapper(final UserNotification userNotification) {
        this.userNotification = userNotification;
    }

    /** Returns the backing UserNotification object */
    public UserNotification getUserNotification() {
        return userNotification;
    }

    public String getNotificationSender() {
        return userNotification.getNotificationSender();
    }

    public void setNotificationSender(final String sender) {
        userNotification.setNotificationSender(sender);
    }

    public String getNotificationSubject() {
        return userNotification.getNotificationSubject();
    }

    public void setNotificationSubject(final String subject) {
        userNotification.setNotificationSubject(subject);
    }

    public String getNotificationMessage() {
        return userNotification.getNotificationMessage();
    }

    public void setNotificationMessage(final String message) {
        userNotification.setNotificationMessage(message);
    }

    public String getNotificationRecipient() {
        return userNotification.getNotificationRecipient();
    }

    public void setNotificationRecipient(final String rcpt) {
        userNotification.setNotificationRecipient(rcpt);
    }

    public Collection<String> getNotificationEventsCollection() {
        return userNotification.getNotificationEventsCollection();
    }

    public void setNotificationEventsCollection(final Collection<String> notificationEventsCollection) {
        userNotification.setNotificationEventsCollection(notificationEventsCollection);
    }
    
    public String toString() {
        return "{GUI Wrapper of " + userNotification.toString() + "}"; 
    }

}
