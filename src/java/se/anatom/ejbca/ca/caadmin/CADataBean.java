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
 
package se.anatom.ejbca.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.io.UnsupportedEncodingException;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

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
 * @version $Id: CADataBean.java,v 1.7 2004-07-13 08:54:01 sbailliez Exp $
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a publisher"
 *   display-name="CADataEB"
 *   name="CAData"
 *   jndi-name="CAData"
 *   local-jndi-name="CADataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="CADataBean"
 *   primkey-field="CAId"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.ca.caadmin.CADataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.ca.caadmin.CADataLocal"
 *
 * @ejb.finder
 *   description="findByName"
 *   signature="se.anatom.ejbca.ca.caadmin.CADataLocal findByName(java.lang.String name)"
 *   query="SELECT DISTINCT OBJECT(a) from CADataBean a WHERE a.name=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT DISTINCT OBJECT(a) from CADataBean a"
 */
public abstract class CADataBean extends BaseEntityBean {

    private CA ca = null;

    private static final Logger log = Logger.getLogger(CADataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method
    */
    public abstract Integer getCAId();

    /**
     * @ejb.persistence
     */
    public abstract void setCAId(Integer caid);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getName();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setName(String name);

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract String getSubjectDN();

    /**
     * @ejb.persistence
     */
    public abstract void setSubjectDN(String subjectdn);
    
    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract int getStatus();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setStatus(int status);
    
    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract long getExpireTime();

    /**
     * @ejb.persistence
     * @ejb.interface-method
     */
    public abstract void setExpireTime(long expiretime);
    
    /**
     * @ejb.persistence
     */
    public abstract String getData();

    /**
     * @ejb.persistence
     */
    public abstract void setData(String data);
    
    
    /** 
     * Method that retrieves the CA from the database.
     * @ejb.interface-method
     */
    public CA getCA() throws java.io.UnsupportedEncodingException{
      if(ca == null){        
        java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(getData().getBytes("UTF8")));
        HashMap data = (HashMap) decoder.readObject();
        decoder.close();
             
        switch(((Integer)(data.get(CA.CATYPE))).intValue()){
            case CAInfo.CATYPE_X509:
              ca = (CA) new X509CA(data, this);
              break;
        }      
      }
            
      return ca;              
    }
    
    /** 
     * Method that saves the CA to database.
     * @ejb.interface-method
     */
    public void setCA(CA ca)  {
       java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
       
       java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
       encoder.writeObject(ca.saveData());
       encoder.close();
        try {
            setData(baos.toString("UTF8"));
        } catch (UnsupportedEncodingException e){
            throw (IllegalStateException)new IllegalStateException().initCause(e);
        }
       this.ca = ca;
       ca.setOwner(this);
    }   
    
    /**
     * Passivates bean, resets CA data.
     */
    public void ejbPassivate() {
        this.ca = null;
    }
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a CA.
     * @param subjectdn
     * @param name of CA
     * @param status initial status
     * @param ca CA to store
     * @return caid
     * @ejb.create-method
     */
    public Integer ejbCreate(String subjectdn, String name, int status, CA ca) throws CreateException {
                
        setCAId(new Integer(subjectdn.hashCode()));
        setName(name);        
        setSubjectDN(subjectdn);
        setStatus(status);        
        
        
        if(ca instanceof X509CA && ca.getCertificateChain().size() != 0){
          setExpireTime(((X509Certificate) ca.getCACertificate()).getNotAfter().getTime());  
          ca.setExpireTime(((X509Certificate) ca.getCACertificate()).getNotAfter()); 
        }  
          
        setCA(ca);        
        log.debug("Created CA "+ name);
        return new Integer(subjectdn.hashCode());
    }

    public void ejbPostCreate(String subjectdn, String name, int status, CA ca) {
        // Do nothing. Required.
    }
    
    
}
