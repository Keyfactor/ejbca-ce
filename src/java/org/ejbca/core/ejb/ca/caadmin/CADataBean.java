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
 
package org.ejbca.core.ejb.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.UpgradeableDataHashMap;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.CVCCA;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;
import org.ejbca.util.CertTools;



/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a ca instance.
 * Information stored:
 * <pre>
 *  caid (Primary key)
 *  name
 *  SubjectDN
 *  type
 *  status
 *  expiretime
 *  data (non searchable data, HashMap stored as XML-String)
 * </pre>
 *
 * @version $Id$
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a publisher"
 *   display-name="CADataEB"
 *   name="CAData"
 *   jndi-name="CAData"
 *   local-jndi-name="CADataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="True"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="CADataBean"
 *   primkey-field="caId"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.persistence table-name = "CAData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.caadmin.CADataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.caadmin.CADataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="org.ejbca.core.ejb.ca.caadmin.CADataLocal findByName(java.lang.String name)"
 *   query="SELECT OBJECT(a) from CADataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from CADataBean a"
 *
 * @ejb.transaction type="Required"
 * 
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CADataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(CADataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method
    */
    public abstract Integer getCaId();

    /**
    */
    public abstract void setCaId(Integer caid);

    /**
     * @ejb.persistence column-name="name"
     * @ejb.interface-method
     */
    public abstract String getName();

    /**
     * @ejb.interface-method
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence column-name="subjectDN"
     * @ejb.interface-method
     */
    public abstract String getSubjectDN();

    /**
     */
    public abstract void setSubjectDN(String subjectdn);
    
    /** from SecConst.CA_XX
     * @ejb.persistence column-name="status"
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);
    
    /**
     * @ejb.persistence column-name="expireTime"
     * @ejb.interface-method
     */
    public abstract long getExpireTime();

    /**
     * @ejb.interface-method
     */
    public abstract void setExpireTime(long expiretime);
    
    /** When was this CA updated in the database
     * @ejb.persistence column-name="updateTime"
     * @ejb.interface-method
     */
    public abstract long getUpdateTime();

    /**
     * @ejb.interface-method
     */
    public abstract void setUpdateTime(long updatetime);
    
    /**
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="data"
     */
    public abstract String getData();

    /**
     */
    public abstract void setData(String data);
    
    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getUpdateTimeAsDate() {
        return new Date(getUpdateTime());
    }

    /** 
     * Method that upgrades a CA, if needed.
     * @throws java.io.UnsupportedEncodingException
     * @throws IllegalKeyStoreException 
     * @ejb.interface-method
     */
    public void upgradeCA() throws java.io.UnsupportedEncodingException, IllegalKeyStoreException {
    	readAndUpgradeCAInternal();
    }
    
    /** 
     * Method that retrieves the CA from the database.
     * @return CA
     * @throws java.io.UnsupportedEncodingException
     * @throws IllegalKeyStoreException 
     * @ejb.interface-method
     */
    public CA getCA() throws java.io.UnsupportedEncodingException, IllegalKeyStoreException {
    	// Because get methods are marked as read-only above, this method will actually not be able to upgrade
    	// use upgradeCA above for that.
    	return readAndUpgradeCAInternal();
    }
    
    /** We have an internal method for this read operation with a side-effect. 
     * This is because getCA() is a read-only method, so the possible side-effect of upgrade will not happen,
     * and therefore this internal method can be called from another non-read-only method, upgradeCA().
     * @return CA
     * @throws java.io.UnsupportedEncodingException
     * @throws IllegalKeyStoreException
     */
    private CA readAndUpgradeCAInternal() throws java.io.UnsupportedEncodingException, IllegalKeyStoreException {
        CA ca = null;
        // First check if we already have a cached instance of the CA
        ca = CACacheManager.instance().getAndUpdateCA(getCaId().intValue(), getStatus(), getExpireTime(), getName(), getSubjectDN());
        boolean isUpdated = false;
        if (ca != null) {
        	if (log.isDebugEnabled()) {
        		log.debug("Found CA ('"+ca.getName()+"', "+getCaId().intValue()+") in cache.");
        	}
        	long update = ca.getCAInfo().getUpdateTime().getTime();
        	long t = getUpdateTime();
        	//log.debug("updateTime from ca = "+update);
        	//log.debug("updateTime from db = "+t);
        	if (update < t) {
        		log.debug("CA '"+ca.getName()+"' has been updated in database, need to refresh cache");
        		isUpdated = true;
        	}
        }
        if ( (ca == null) || isUpdated) {
        	log.debug("Re-reading CA from database: "+getCaId().intValue());
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);
            
            // If CA-data is upgraded we want to save the new data, so we must get the old version before loading the data 
            // and perhaps upgrading
            float oldversion = ((Float) data.get(UpgradeableDataHashMap.VERSION)).floatValue();
            switch(((Integer)(data.get(CA.CATYPE))).intValue()){
                case CAInfo.CATYPE_X509:
                    ca = new X509CA(data, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate(), new Date(getExpireTime()));                    
                    break;
                case CAInfo.CATYPE_CVC:
                    ca = new CVCCA(data, getCaId().intValue(), getSubjectDN(), getName(), getStatus(), getUpdateTimeAsDate());                    
                    break;
            }
            boolean upgradedExtendedService = ca.upgradeExtendedCAServices();
            // Compare old version with current version and save the data if there has been a change
            if ( ((ca != null) && (Float.compare(oldversion, ca.getVersion()) != 0))
            	  || upgradedExtendedService) {
            	// Make sure we upgrade the CAToken as well, if needed
                ca.getCAToken();
                setCA(ca);
                log.debug("Stored upgraded CA ('"+ca.getName()+"', "+getCaId().intValue()+") with version "+ca.getVersion());
            }
            // We have to do the same if CAToken was upgraded
            // Add CA to the cache
            CACacheManager.instance().addCA(getCaId().intValue(), ca);
        }
        return ca;              
    }
    
    /** 
     * Method that saves the CA to database.
     * @ejb.interface-method
     */
    public void setCA(CA ca) throws UnsupportedEncodingException {
        // We must base64 encode string for UTF safety
        HashMap a = new Base64PutHashMap();
        a.putAll((HashMap)ca.saveData());
        
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        log.debug("Saving CA data with length: "+data.length()+" for CA '"+ca.getName()+"'.");
        setData(data);
        setUpdateTime(new Date().getTime());
        // We have to update status as well, because it is kept in it's own database column, but only do that if it was actually provided in the request
        if (ca.getStatus() > 0) {
            setStatus(ca.getStatus());        	
        }
        // remove the CA from the cache to force an update the next time we load it
        CACacheManager.instance().removeCA(getCaId().intValue());
        // .. and we try to load it right away
        try {
			readAndUpgradeCAInternal();
		} catch (IllegalKeyStoreException e) {
			// Ok.. so we failed after all.. try loading it next time so the error is displayed as it used to..
	        CACacheManager.instance().removeCA(getCaId().intValue());
		}
    }   
    
    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a CA.
     * @param subjectdn
     * @param name of CA
     * @param status initial status from SecConst.CA_XX;
     * @param ca CA to store
     * @return caid
     * @ejb.create-method
     */
    public Integer ejbCreate(String subjectdn, String name, int status, CA ca) throws CreateException {
    	try {
    		
    		setCaId(new Integer(subjectdn.hashCode()));
    		setName(name);        
    		setSubjectDN(subjectdn);
    		
    		if (ca.getCertificateChain().size() != 0) {
    			Certificate cacert = ca.getCACertificate();
    			setExpireTime(CertTools.getNotAfter(cacert).getTime());  
    			ca.setExpireTime(CertTools.getNotAfter(cacert)); 
    		}  
    		// Set status, because it can occur in the ca object as well, but we think the one passed as argument here is what
    		// is desired primarily, so make sure we set that
    		ca.setStatus(status);        
    		setCA(ca);
    		if (log.isDebugEnabled()) {
    			log.debug("Created CA "+ name);
    		}
    		return new Integer(subjectdn.hashCode());
    	} catch(java.io.UnsupportedEncodingException e) {
    		log.error("CAData caught exception trying to create: ", e);
    		throw new CreateException(e.toString());
    	}
    }

    public void ejbPostCreate(String subjectdn, String name, int status, CA ca) {
        // Do nothing. Required.
    }
    
    
}
