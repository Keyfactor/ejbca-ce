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
 
package se.anatom.ejbca.ca.store;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.util.CertTools;


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
 * @version $Id: CertReqHistoryDataBean.java,v 1.2 2005-12-27 14:18:55 anatom Exp $
 *
 * @ejb.bean description="This enterprise bean entity containing historical record over data user to generate a users certificate"
 * display-name="CertReqHistoryDataEB"
 * name="CertReqHistoryData"
 * view-type="local"
 * type="CMP"
 * reentrant="False"
 * cmp-version="2.x"
 * transaction-type="Container"
 * schema="CertReqHistoryDataBean"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.pk class="se.anatom.ejbca.ca.store.CertReqHistoryDataPK"
 * extends="java.lang.Object"
 * implements="java.io.Serializable"
 *
 * @ejb.home
 * generate="local"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ca.store.CertReqHistoryDataLocalHome"
 *
 * @ejb.interface
 * generate="local"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ca.store.CertReqHistoryDataLocal"
 *
 * @ejb.finder description="findByIssuerDNSerialNumber"
 * signature="Collection findByIssuerDNSerialNumber(java.lang.String issuerDN, java.lang.String serialNumber)"
 * query="SELECT DISTINCT OBJECT(a) from CertReqHistoryDataBean a WHERE a.issuerDN=?1 AND a.serialNumber=?2"
 *
 * @ejb.finder description="findByUsername"
 * signature="Collection findByUsername(java.lang.String username)"
 * query="SELECT DISTINCT OBJECT(a) from CertReqHistoryDataBean a WHERE  a.username=?1"
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
     * @ejb.persistence
     * 
     */
    public abstract String getIssuerDN();

    /**
     * Use setIssuer instead
     *
     * @param issuerDN issuer dn
     *
     * @ejb.persistence
     */
    public abstract void setIssuerDN(String issuerDN);

    /**
     * Fingerprint of certificate
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return fingerprint
     * @ejb.persistence
     * @ejb.interface-method
     * @ejb.pk-field 
     */
    public abstract String getFingerprint();

    /**
     * Fingerprint of certificate
     * Shouldn't be set after creation.
     * 
     * @param fingerprint fingerprint
     * @ejb.persistence
     */
    public abstract void setFingerprint(String fingerprint);

    /**
     * Serialnumber formated as BigInteger.toString()
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return serial number
     * @ejb.persistence
     */
    public abstract String getSerialNumber();

    /**
     * Serialnumber formated as BigInteger.toString()
     * Shouldn't be set after creation.
     * 
     * @param serialNumber serial number
     * @ejb.persistence
     */
    public abstract void setSerialNumber(String serialNumber);

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return timestamp 
     * @ejb.persistence
     */
    public abstract long getTimestamp();

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     * Shouldn't be set after creation.
     *
     * @param timestamp when certificate request info was stored
     * @ejb.persistence
     */
    public abstract void setTimestamp(long timestamp);


    /**
     * UserDataVO in xmlencoded String format
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return  xmlencoded encoded UserDataVO
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getUserDataVO();

    /**
     * UserDataVO in  xmlencoded String format
     * Shouldn't be set after creation.
     *
     * @param userDataVO xmlencoded encoded UserDataVO
     * @ejb.persistence
     */
    public abstract void setUserDataVO(String userDataVO);

    /**
     * username in database
     * Should be used outside of entity bean, use getCertReqHistory instead
     *
     * @return username
     * @ejb.persistence
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * Shouldn't be set after creation.
     *
     * @param username username
     *
     * @see se.anatom.ejbca.util.StringTools
     * @ejb.persistence
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
        // Exctract fields to store with the certificate.
        X509Certificate tmpcert;

        tmpcert = (X509Certificate) incert;
        String fingerprint = CertTools.getFingerprintAsString(tmpcert);
        setFingerprint(fingerprint);
        setIssuerDN(CertTools.getIssuerDN(tmpcert));
        log.debug("Creating certreqhistory data, serial=" + tmpcert.getSerialNumber().toString() + ", issuer=" + getIssuerDN());
        setSerialNumber(tmpcert.getSerialNumber().toString());
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
