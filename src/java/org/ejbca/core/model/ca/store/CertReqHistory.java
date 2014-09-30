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
package org.ejbca.core.model.ca.store;

import java.io.Serializable;
import java.util.Date;

import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Value object class containing the data stored in the 
 * CertReqHistory Entity Bean. See constructor for details of its fields.
 * 
 * @version $Id$
 * @see org.ejbca.core.ejb.ca.store.CertReqHistoryDataBean  
 */

public class CertReqHistory implements Serializable{
    private static final long serialVersionUID = -5449568418691275341L;
    private String fingerprint;
    private String serialNumber;
    private String issuerDN;
    private String username;
    private Date timestamp;
    private EndEntityInformation endEntityInformation;
    
    /**
     * @param fingerprint the PK of the certificate in the CertificateDataBean
     * @param serialNumber of the certificate 
     * @param issuerDN DN of the CA issuing the certificate
     * @param username of the user used in the certificate request.
     * @param timestamp when the certicate was created.
     * @param endEntityInformation the userdata used to create the certificate.
     */
    public CertReqHistory(String fingerprint, String serialNumber,
            String issuerDN, String username, Date timestamp,
            EndEntityInformation endEntityInformation) {
        super();
        this.fingerprint = fingerprint;
        this.serialNumber = serialNumber;
        this.issuerDN = issuerDN;
        this.username = username;
        this.timestamp = timestamp;
        this.endEntityInformation = endEntityInformation;
    }
    /**
     * @return Returns the issuerDN.
     */
    public String getFingerprint() {
        return fingerprint;
    }
    /**
     * @return Returns the issuerDN.
     */
    public String getIssuerDN() {
        return issuerDN;
    }
    /**
     * @return Returns the serialNumber.
     */
    public String getSerialNumber() {
        return serialNumber;
    }
    /**
     * @return Returns the timestamp.
     */
    public Date getTimestamp() {
        return timestamp;
    }
    /**
     * @return Returns the EndEntityInformation.
     */
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }
    /**
     * @return Returns the username.
     */
    public String getUsername() {
        return username;
    }
    

}
