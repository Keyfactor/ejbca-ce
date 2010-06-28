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
 
package org.ejbca.core.ejb.ca.store;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;






/**
 * Entity Bean storing historical information about the data user to 
 * create a certificate. Information stored:
 * <pre>
 * Primary Key (fingerprint, String)
 * Issuer DN (issuerDN)
 * Serial number (serialNumber)
 * Username (username);
 * Timestamp (timestamp)
 * UserDataVO (userAdminData)
 * </pre>
 *
 * @version $Id$
 *
 * @ejb.bean description="This enterprise bean entity containing historical record over data user to generate a users certificate"
 * display-name="CertReqHistoryDataEB"
 * name="CertReqHistoryData"
 * jndi-name="CertReqHistoryData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertReqHistoryDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.persistence table-name = "CertReqHistoryData"
 * 
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="org.ejbca.core.ejb.ca.store.CertReqHistoryDataLocal"
 *
 * @ejb.finder description="findByIssuerDNSerialNumber"
 * signature="Collection findByIssuerDNSerialNumber(java.lang.String issuerDN, java.lang.String serialNumber)"
 * query="SELECT OBJECT(a) from CertReqHistoryDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2"
 *
 * @ejb.finder description="findByUsername"
 * signature="Collection findByUsername(java.lang.String username)"
 * query="SELECT OBJECT(a) from CertReqHistoryDataBean a WHERE  a.username=?1"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class CertReqHistoryDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(CertReqHistoryDataBean.class);

    /**
     * DN of issuer of certificate
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return issuer dn
     * @ejb.persistence column-name="issuerDN"
     * 
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * Fingerprint of certificate
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return fingerprint
     * @ejb.persistence column-name="fingerprint"
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getFingerprint();

    /**
     * Fingerprint of certificate
     * Shouldn't be set after creation.
     * 
     * @param fingerprint fingerprint
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * Serialnumber formated as BigInteger.toString()
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return serial number
     * @ejb.persistence column-name="serialNumber"
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     * Shouldn't be set after creation.
     * 
     * @param serialNumber serial number
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return timestamp 
     * @ejb.persistence column-name="timestamp"
     */
    public abstract long getTimestamp();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Shouldn't be set after creation.
     *
     * @param timestamp when certificate request info was stored
     */
    public abstract void setTimestamp(long timestamp);


    /**
     * UserDataVO in xmlencoded String format
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return  xmlencoded encoded UserDataVO
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="userDataVO"
     */
    public abstract String getUserDataVO();

    /**
     * UserDataVO in  xmlencoded String format
     * Shouldn't be set after creation.
     *
     * @param userDataVO xmlencoded encoded UserDataVO
     */
    public abstract void setUserDataVO(String userDataVO);

    /**
     * username in database
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return username
     * @ejb.persistence column-name="username"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * Shouldn't be set after creation.
     *
     * @param username username
     *
     * @see org.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    //
    // Public business methods used to help us manage certificates
    //

    /**
     * Returns the value object containing the information of the entity bean.
     * This is the method that should be used to retreive cert req history 
     * correctly.
     *
     * @return certificate request history object
     * @ejb.interface-method
     */
    public CertReqHistory getCertReqHistory() {
    	
	    java.beans.XMLDecoder decoder;
		try {
		  decoder =
			new java.beans.XMLDecoder(
					new java.io.ByteArrayInputStream(getUserDataVO().getBytes("UTF8")));
		} catch (UnsupportedEncodingException e) {
		  throw new EJBException(e);
		}
		UserDataVO useradmindata  = (UserDataVO) decoder.readObject();	
		decoder.close();

        return new CertReqHistory(this.getFingerprint(),this.getSerialNumber(),
        		this.getIssuerDN(),this.getUsername(),new Date(this.getTimestamp()),
				useradmindata);
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding info about a request data at the time the certificate was issued.
     * 
     * @param incert the certificate issued
     * @param UserDataVO, the data used to issue the certificate. 
     *
     * @return primary key
     * @ejb.create-method
     */
    public CertReqHistoryDataPK ejbCreate(Certificate incert, UserDataVO useradmindata)
        throws CreateException {
        // Extract fields to store with the certificate.
        String fingerprint = CertTools.getFingerprintAsString(incert);
        setFingerprint(fingerprint);
        setIssuerDN(CertTools.getIssuerDN(incert));
        if (log.isDebugEnabled()) {
        	log.debug("Creating certreqhistory data, serial=" + CertTools.getSerialNumberAsString(incert) + ", issuer=" + getIssuerDN());
        }
        setSerialNumber(CertTools.getSerialNumber(incert).toString());
        setTimestamp(new Date().getTime());
                	
    	setUsername(useradmindata.getUsername());
    	try {
            // Save the user admin data in xml encoding.
    		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

    		java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
    		encoder.writeObject(useradmindata);
    		encoder.close();

            if (log.isDebugEnabled()) {
               log.debug("useradmindata: \n" + baos.toString("UTF8"));
            }
   			setUserDataVO(baos.toString("UTF8"));            
        } catch (UnsupportedEncodingException e) {
            throw new EJBException(e);    	                                              
        } 
        return null;
    }

    /**
     * required method, does nothing
     *
     * @param incert certificate
     * @param UserDataVO, the data used to issue the certificate. 
     */
    public void ejbPostCreate(Certificate incert, UserDataVO useradmindata) {
        // Do nothing. Required.
    }
}
