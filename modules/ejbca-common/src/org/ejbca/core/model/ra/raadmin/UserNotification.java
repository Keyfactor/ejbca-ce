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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.endentity.EndEntityConstants;

/**
 * Class holding information about user notification sent when a user transitions through
 * the work-flow. 
 * This class is implemented on top of a HashMap, so it can easily be upgraded with new features
 * such as different notification actions (apart from email) etc.
 * 
 * @version $Id$
 */
// TODO: Don't worry about the warning below, a fix is in the pipeline -mikek
public class UserNotification extends HashMap implements Serializable, Cloneable {

	/** This is the data stored in this object.
	 * A hashmap is good because it serializes nicely and data can be upgraded without changing
	 * serialversion uid
	 */
    private HashMap<String, String> data;

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
    public static final String EVENTS_USERENROL = String.valueOf(EndEntityConstants.STATUS_GENERATED);
    
    // protected in order to upgrade in EndEntityProfile.upgrade()
    // Use private for new fields.
    protected static final String NOTIFICATIONSENDER     = "NOTIFICATIONSENDER";
    protected static final String NOTIFICATIONSUBJECT    = "NOTIFICATIONSSUBJECT";
    protected static final String NOTIFICATIONMESSAGE    = "NOTIFICATIONSMESSAGE";
    private static final String   NOTIFICATIONRECIPIENT  = "NOTIFICATIONRECIPIENT";
    private static final String   NOTIFICATIONEVENTS     = "NOTIFICATIONEVENTS";

    public UserNotification() {
    	data = new HashMap<String, String>();
    }
    
    public UserNotification(String sender, String rcpt, String subject, String message, String events) {
    	data = new HashMap<String, String>();
    	setNotificationSender(sender);
    	setNotificationSubject(subject);
    	setNotificationMessage(message);
    	setNotificationRecipient(rcpt);
    	setNotificationEvents(events);
    }

    public String getNotificationSender(){
    	String ret = "";
    	if(data.get(NOTIFICATIONSENDER) != null) {
    		ret = (String) data.get(NOTIFICATIONSENDER);
    	}
    	return ret;
    }
    
    public void setNotificationSender(String sender){
    	data.put(NOTIFICATIONSENDER, sender);    		
    }
    
    public String getNotificationSubject(){
    	String ret = "";
    	if(data.get(NOTIFICATIONSUBJECT) != null) {
    		ret = (String) data.get(NOTIFICATIONSUBJECT);
    	}
    	return ret;
    }
    
    public void setNotificationSubject(String subject){
    	data.put(NOTIFICATIONSUBJECT, subject);    		
    }
        
    public String getNotificationMessage(){
    	String ret = "";
    	if(data.get(NOTIFICATIONMESSAGE) != null) {
    		ret = (String) data.get(NOTIFICATIONMESSAGE);
    	}
    	return ret;
    }
    
    public void setNotificationMessage(String message){
    	data.put(NOTIFICATIONMESSAGE, message);
    }

    public String getNotificationRecipient(){
    	String ret = "";
    	if(data.get(NOTIFICATIONRECIPIENT) != null) {
    		ret = (String) data.get(NOTIFICATIONRECIPIENT);
    	}
    	return ret;
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
    public String getNotificationEvents(){
    	String ret = "";
    	if(data.get(NOTIFICATIONEVENTS) != null) {
    		ret = (String) data.get(NOTIFICATIONEVENTS);
    	}
    	return ret;
    }

    /** Returns a collection view of getNotificationEvents.
     * 
     * @return A Collection with String values (String.valueOf(EndEntityConstants.STATUS_NEW etc), or an empty Collection, never null.
     */
    public Collection<String> getNotificationEventsCollection(){
    	String events = getNotificationEvents();
    	ArrayList<String> ret = new ArrayList<String>();
    	if (StringUtils.isNotEmpty(events)) {
    		StringTokenizer tokenizer = new StringTokenizer(events, ";", false);
            while (tokenizer.hasMoreTokens()) {
            	ret.add(tokenizer.nextToken());
            }
    	}
    	return ret;
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
