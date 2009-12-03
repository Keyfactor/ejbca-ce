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

package org.ejbca.core.ejb.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.ejbca.util.GUIDGenerator;

/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing publisher failure data. Data is stored here when publishing to a publisher fails. Using this data publishing
 * can be tried again. This data bean should not duplicate data completely, but holds this:
 * 
 * - Information needed for scheduling of republishing, such as publish dates, retry counter and last failure message.
 * - Information which is volatile on other places in the database, and we need to publish this data as it was at the time of publishing.
 *   In this case it is UserData, which can change because every user can have several certificates with different DN, the password is re-set
 *   when a certificate is issued etc.
 * - Foreign keys to information which is not volatile.
 *   In this case this is keys to CertificateData and CRLData. For CertificateData we always want to publish the latest information, even if it changed
 *   since we failed to publish. This is so there should be no chance that a revocation is overwritten with a good status if the 
 *   publish events would happen out of order.
 *   
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents publisher failure data"
 *   display-name="PublisherQueueDataEB"
 *   name="PublisherQueueData"
 *   jndi-name="PublisherQueueData"
 *   local-jndi-name="PublisherQueueDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="PublisherQueueDataBean"
 *   primkey-field="pk"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.String"
 *   
 * @ejb.persistence table-name = "PublisherQueueData"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.publisher.PublisherQueueDataLocal"
 *
 * @ejb.finder
 *   description="finds queue data by publisherId"
 *   signature="java.util.Collection findDataByPublisherIdAndStatus(int publisherId, int status)"
 *   query="SELECT OBJECT(a) from PublisherQueueDataBean a WHERE a.publisherId=?1 and a.publishStatus=?2"
 * 
 * @ejb.finder
 *   description="finds queue data by fingerprint"
 *   signature="java.util.Collection findDataByFingerprint(java.lang.String fingerprint)"
 *   query="SELECT OBJECT(a) from PublisherQueueDataBean a WHERE a.fingerprint=?1"
 *   
 * @ejb.transaction type="Required"
 *
 * @author Tomas Gustavsson
 * @version $Id$
 * 
 */
public abstract class PublisherQueueDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(PublisherQueueDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="pk"
     * @ejb.interface-method
     */
    public abstract String getPk();
    public abstract void setPk(String pk);

    /**
     * @ejb.persistence column-name="timeCreated"
     * @ejb.interface-method view-type="local"
     */
    public abstract long getTimeCreated();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTimeCreated(long timeCreated);

    /**
     * @ejb.persistence column-name="lastUpdate"
     * @ejb.interface-method view-type="local"
     */
    public abstract long getLastUpdate();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setLastUpdate(long lastUpdate);

    /** PublishStatus is one of PublisherQueueData.STATUS_PENDING, FAILED or SUCCESS.
     * 
     * @ejb.persistence column-name="publishStatus"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getPublishStatus();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setPublishStatus(int publishStatus);

    /**
     * @ejb.persistence column-name="tryCounter"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getTryCounter();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTryCounter(int tryCounter);

    /** PublishType is one of PublishQueueData.PUBLISH_TYPE_CERT or CRL
     * 
     * @ejb.persistence column-name="publishType"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getPublishType();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setPublishType(int publishType);

    /** Foreign key to certificate of crl
     * 
     * @ejb.persistence column-name="fingerprint"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getFingerprint();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * @ejb.persistence column-name="publisherId"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getPublisherId();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setPublisherId(int publisherId);

    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="volatileData"
     */
    public abstract String getVolatileData();

    /**
     */
    public abstract void setVolatileData(String queueData);

    /**
     * Method that returns the PublisherQueueVolatileData data and updates it if necessary.
     *
     * @ejb.interface-method view-type="local"
     */
    public PublisherQueueVolatileData getPublisherQueueVolatileData() {
    	// VolatileData is optional in publisher queue data
    	PublisherQueueVolatileData ret = null;
    	try {
    		String vd = getVolatileData();
    		if ( (vd != null) && (vd.length() > 0) ) {
    			byte[] databytes = vd.getBytes("UTF8");    			
    			java.beans.XMLDecoder decoder;
    			decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(databytes));
    			HashMap h = (HashMap) decoder.readObject();
    			decoder.close();
    			// Handle Base64 encoded string values
    			HashMap data = new Base64GetHashMap(h);
    			ret = new PublisherQueueVolatileData();
    			ret.loadData(data);
    			if (ret.isUpgraded()) {
    				setPublisherQueueVolatileData(ret);
    			}    		
    		}
    	} catch (UnsupportedEncodingException e) {
    		throw new EJBException(e);
    	}
    	return ret;
    }

    /**
     * Method that saves the PublisherQueueData data to database.
     *
     * @ejb.interface-method view-type="local"
     */
    public void setPublisherQueueVolatileData(PublisherQueueVolatileData qd) {
    	// qd is optional in publisher queue data
    	if (qd != null) {
            // We must base64 encode string for UTF safety
            HashMap a = new Base64PutHashMap();
            a.putAll((HashMap)qd.saveData());
            
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
            encoder.writeObject(a);
            encoder.close();

            try {
                if (log.isDebugEnabled()) {
                    log.debug("PublisherQueueVolatileData: \n" + baos.toString("UTF8"));
                }
                setVolatileData(baos.toString("UTF8"));
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }	
    	}
    }


    //
    // Fields required by Container
    //
    /**
     * Passivates bean.
     */
    public void ejbPassivate() {
        // Do nothing. Required.
    }


    /**
     * Entity Bean.
     *
     * @param publishType is one of PublishQueueData.PUBLISH_TYPE_CERT or CRL
     * @return null
     * @ejb.create-method view-type="local"
     */
    public String ejbCreate(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData, int publishStatus) throws CreateException {
    	String pk = GUIDGenerator.generateGUID(this); 
		setPk(pk);
		Date now = new Date();
        setTimeCreated(now.getTime());
        setLastUpdate(0);
        setPublishStatus(publishStatus);
        setTryCounter(0);
        setPublishType(publishType);
        setFingerprint(fingerprint);
        setPublisherId(publisherId);
        setPublisherQueueVolatileData(queueData);
        log.debug("Created Publisher queue data " + pk);
        return null;
    }

    public void ejbPostCreate(int publisherId, int publishType, String fingerprint, PublisherQueueVolatileData queueData, int publishStatus) {
        // Do nothing. Required.
    }
}
