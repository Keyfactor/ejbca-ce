package org.ejbca.core.model.ra.raadmin;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.core.model.ra.UserDataConstants;

/**
 * Class holding information about user notification sent when a user transitions through
 * the work-flow. 
 * This class is implemented on top of a HashMap, so it can easily be upgraded with new features
 * such as different notification actions (apart from email) etc.
 * 
 * @author tomas
 * @version $Id: UserNotification.java,v 1.5 2007-12-06 16:39:09 anatom Exp $
 */
public class UserNotification extends HashMap implements Serializable, Cloneable {

	/** This is the data stored in this object.
	 * A hashmap is good because it serializes nicely and data can be upgraded without changing
	 * serialversion uid
	 */
    private HashMap data;

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
    public static final String   RCPT_PLUGIN    = "PLUGIN";

    public static final String EVENTS_EDITUSER = String.valueOf(UserDataConstants.STATUS_NEW)+";"+String.valueOf(UserDataConstants.STATUS_KEYRECOVERY)+";"+String.valueOf(UserDataConstants.STATUS_INITIALIZED);
    public static final String EVENTS_USERENROL = String.valueOf(UserDataConstants.STATUS_GENERATED);
    
    // protected in order to upgrade in EndEntityProfile.upgrade()
    // Use private for new fields.
    protected static final String NOTIFICATIONSENDER     = "NOTIFICATIONSENDER";
    protected static final String NOTIFICATIONSUBJECT    = "NOTIFICATIONSSUBJECT";
    protected static final String NOTIFICATIONMESSAGE    = "NOTIFICATIONSMESSAGE";
    private static final String   NOTIFICATIONRECIPIENT  = "NOTIFICATIONRECIPIENT";
    private static final String   NOTIFICATIONEVENTS     = "NOTIFICATIONEVENTS";

    public UserNotification() {
    	data = new HashMap();
    }
    
    public UserNotification(String sender, String rcpt, String subject, String message, String events) {
    	data = new HashMap();
    	setNotificationSender(sender);
    	setNotificationSubject(subject);
    	setNotificationMessage(message);
    	setNotificationRecipient(rcpt);
    	setNotificationEvents(events);
    }

    public String getNotificationSender(){
    	if(data.get(NOTIFICATIONSENDER) == null)
    		return "";
    	return (String) data.get(NOTIFICATIONSENDER);
    }
    
    public void setNotificationSender(String sender){
    	data.put(NOTIFICATIONSENDER, sender);    		
    }
    
    public String getNotificationSubject(){
    	if(data.get(NOTIFICATIONSUBJECT) == null)
    		return "";
    	return (String) data.get(NOTIFICATIONSUBJECT);
    }
    
    public void setNotificationSubject(String subject){
    	data.put(NOTIFICATIONSUBJECT, subject);    		
    }
        
    public String getNotificationMessage(){
    	if(data.get(NOTIFICATIONMESSAGE) == null)
    		return "";
    	return (String) data.get(NOTIFICATIONMESSAGE);
    }
    
    public void setNotificationMessage(String message){
    	data.put(NOTIFICATIONMESSAGE, message);
    }

    public String getNotificationRecipient(){
    	if(data.get(NOTIFICATIONRECIPIENT) == null)
    		return "";
    	return (String) data.get(NOTIFICATIONRECIPIENT);
    }
    
    /**
     * Recipient of the notification
     * @param rcpt can be constants UserNotification.RCPT_XX or an email address. Several recipients can be specified separated by ;
     */
    public void setNotificationRecipient(String rcpt){
    	data.put(NOTIFICATIONRECIPIENT, rcpt);
    }

    /** list of UserDataConstant.STATUS_XX separated by ;. See constants EVENTS_XX for helper events.
     * example 'String.valueOf(UserDataConstants.STATUS_NEW)+";"+String.valueOf(UserDataConstants.STATUS_KEYRECOVERY)'
     * @return String with integer values separated by ;
     * @see UserNotification.EVENTS_EDITUSER
     */
    public String getNotificationEvents(){
    	if(data.get(NOTIFICATIONEVENTS) == null)
    		return "";
    	return (String) data.get(NOTIFICATIONEVENTS);
    }

    /** Returns a collection view of getNotificationEvents.
     * 
     * @return A Collection with String values (String.valueOf(UserDataConstants.STATUS_NEW etc), or an empty Collection, never null.
     */
    public Collection getNotificationEventsCollection(){
    	String events = getNotificationEvents();
    	ArrayList ret = new ArrayList();
    	if (StringUtils.isNotEmpty(events)) {
    		StringTokenizer tokenizer = new StringTokenizer(events, ";", false);
            while (tokenizer.hasMoreTokens()) {
            	ret.add(tokenizer.nextToken());
            }
    	}
    	return ret;
    }

    /** list of UserDataConstant.STATUS_XX separated by ;. See constants EVENTS_XX for helper events.
     * example 'String.valueOf(UserDataConstants.STATUS_NEW)+";"+String.valueOf(UserDataConstants.STATUS_KEYRECOVERY)'
     * @param String with integer values separated by ;
     * @see UserNotification.EVENTS_EDITUSER
     */
    public void setNotificationEvents(String events){
    	data.put(NOTIFICATIONEVENTS, events);
    }

    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        StringBuffer strBuffer = new StringBuffer("UserNotification(");

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

    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
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

    /**
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        return this.toString().hashCode();
    }
    
}
