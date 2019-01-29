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

package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.StringTools;

/**
 * Class holding information about user notification sent when a user transitions through
 * the work-flow.
 * <p> 
 * This class is implemented on top of a HashMap, so it can easily be upgraded with new features
 * such as different notification actions (apart from email) etc.
 * <p>
 * This class used to extend HashMap until EJBCA 7.0.0, which was unnecessary because the
 * "data" map contains all the information. When deserialized on 7.0.0 and later,
 * the redundant HashMap superclass will be ignored if present.
 * 
 * @version $Id$
 */
public class UserNotification implements Serializable, Cloneable {

	/** This is the data stored in this object.
	 * A hashmap is good because it serializes nicely and data can be upgraded without changing
	 * serialversion uid
	 */
    private final HashMap<String, String> data = new LinkedHashMap<>();

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    private static final long serialVersionUID = -100L;

    /** Recipient of notification is the user */
    public static final String   RCPT_USER     = "USER";
    /** recipient of notification is the admin of the user */
    public static final String   RCPT_CUSTOM    = "CUSTOM";

    public static final String EVENTS_EDITUSER = EndEntityConstants.STATUS_NEW+";"+EndEntityConstants.STATUS_KEYRECOVERY+";"+EndEntityConstants.STATUS_INITIALIZED;
    public static final String EVENTS_USERENROLL = String.valueOf(EndEntityConstants.STATUS_GENERATED);
    
    // protected in order to upgrade in EndEntityProfile.upgrade()
    // Use private for new fields.
    protected static final String NOTIFICATIONSENDER     = "NOTIFICATIONSENDER";
    protected static final String NOTIFICATIONSUBJECT    = "NOTIFICATIONSSUBJECT";
    protected static final String NOTIFICATIONMESSAGE    = "NOTIFICATIONSMESSAGE";
    private static final String   NOTIFICATIONRECIPIENT  = "NOTIFICATIONRECIPIENT";
    private static final String   NOTIFICATIONEVENTS     = "NOTIFICATIONEVENTS";

    public UserNotification() {
    }
    
    public UserNotification(String sender, String rcpt, String subject, String message, String events) {
    	setNotificationSender(sender);
    	setNotificationSubject(subject);
    	setNotificationMessage(message);
    	setNotificationRecipient(rcpt);
    	setNotificationEvents(events);
    }

    public String getNotificationSender(){
    	return StringUtils.defaultString(data.get(NOTIFICATIONSENDER));
    }
    
    public void setNotificationSender(String sender){
    	data.put(NOTIFICATIONSENDER, sender);    		
    }
    
    public String getNotificationSubject(){
    	return StringUtils.defaultString(data.get(NOTIFICATIONSUBJECT));
    }
    
    public void setNotificationSubject(String subject){
    	data.put(NOTIFICATIONSUBJECT, subject);    		
    }
        
    public String getNotificationMessage(){
    	return StringUtils.defaultString(data.get(NOTIFICATIONMESSAGE));
    }
    
    public void setNotificationMessage(String message){
    	data.put(NOTIFICATIONMESSAGE, message);
    }

    public String getNotificationRecipient(){
    	return StringUtils.defaultString(data.get(NOTIFICATIONRECIPIENT));
    }
    
    /**
     * Recipient of the notification
     * @param rcpt can be constants UserNotification.RCPT_XX or an email address. Several recipients can be specified separated by ;
     */
    public void setNotificationRecipient(String rcpt){
    	data.put(NOTIFICATIONRECIPIENT, rcpt);
    }

    /** list of UserDataConstant.STATUS_XX separated by ;. See constants EVENTS_XX for helper events.
     * example 'String.valueOf(EndEntityConstants.STATUS_NEW)+";"+String.valueOf(EndEntityConstants.STATUS_KEYRECOVERY)'
     * @return String with integer values separated by ;
     * @see UserNotification.EVENTS_EDITUSER
     */
    public String getNotificationEvents() {
    	return StringUtils.defaultString(data.get(NOTIFICATIONEVENTS));
    }

    /** Returns a collection view of getNotificationEvents.
     * 
     * @return A Collection with String values (String.valueOf(EndEntityConstants.STATUS_NEW etc), or an empty Collection, never null.
     */
    public Collection<Integer> getNotificationEventsCollection() {
    	final String events = getNotificationEvents();
    	return StringTools.idStringToListOfInteger(events, EndEntityProfile.SPLITCHAR);
    }
    
    public void setNotificationEventsCollection(final Collection<Integer> notificationEventsCollection){
        final String notificationEvents = StringUtils.join(notificationEventsCollection, ";");
        data.put(NOTIFICATIONEVENTS, notificationEvents);
    }

    /** list of UserDataConstant.STATUS_XX separated by ;. See constants EVENTS_XX for helper events.
     * example 'String.valueOf(EndEntityConstants.STATUS_NEW)+";"+String.valueOf(EndEntityConstants.STATUS_KEYRECOVERY)'
     * @param String with integer values separated by ;
     * @see UserNotification.EVENTS_EDITUSER
     */
    public void setNotificationEvents(String events){
    	data.put(NOTIFICATIONEVENTS, events);
    }

    @Override
    public String toString() {
    	final StringBuilder strBuffer = new StringBuilder("UserNotification(");
        strBuffer.append("sender=");
        strBuffer.append(this.getNotificationSender());
        strBuffer.append(", rcpt=");
        strBuffer.append(this.getNotificationRecipient());
        strBuffer.append(", subject=");
        strBuffer.append(this.getNotificationSubject());
        strBuffer.append(", message=");
        strBuffer.append(this.getNotificationMessage());
        strBuffer.append(", events=");
        strBuffer.append(this.getNotificationEvents());
        strBuffer.append(")");
        return strBuffer.toString();
    }

    @Override
    public boolean equals(Object obj) {
        boolean ret = false;
        if((obj == null) || !(obj instanceof UserNotification)) {
            return ret;
        }
        UserNotification o = (UserNotification)obj;
        if ( StringUtils.equals(this.getNotificationSender(), o.getNotificationSender()) &&
        	 StringUtils.equals(this.getNotificationRecipient(), o.getNotificationRecipient()) &&
        	 StringUtils.equals(this.getNotificationSubject(), o.getNotificationSubject()) &&
        	 StringUtils.equals(this.getNotificationMessage(), o.getNotificationMessage()) &&
        	 StringUtils.equals(this.getNotificationEvents(), o.getNotificationEvents()) ) {
        	ret = true;
        }
        return ret;
    }
    
    @Override
    public int hashCode() {
        return this.toString().hashCode();
    }
    
}
