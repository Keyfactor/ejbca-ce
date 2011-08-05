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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.ca.store.CertReqHistory;

/**
 * Interface for certificate store operations
 *
 * @version $Id$
 */
public interface CertReqHistorySession {

    /**
     * Method used to add a CertReqHistory to database
     * 
     * @param admin calling the methods
     * @param cert the certificate to store (Only X509Certificate used for now)
     * @param useradmindata the user information used when issuing the certificate.
     */
    public void addCertReqHistoryData(AuthenticationToken admin, Certificate cert, EndEntityInformation useradmindata);

    /**
     * Method to remove CertReqHistory data.
     * @param admin
     * @param certFingerprint the primary key.
     */
    public void removeCertReqHistoryData(AuthenticationToken admin, String certFingerprint);

    /**
     * Retrieves the certificate request data belonging to given certificate serialnumber and issuerdn
     * 
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
     * @param admin
     * @param certificateSN serial number of the certificate
     * @param issuerDN
     * @return the CertReqHistory or null if no data is stored with the certificate.
     */
    public CertReqHistory retrieveCertReqHistory(AuthenticationToken admin, BigInteger certificateSN, String issuerDN);

    /**
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
     * @return all certificate request data belonging to a user.
     */
    public List<CertReqHistory> retrieveCertReqHistory(AuthenticationToken admin, String username);
}
