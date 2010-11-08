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
package org.cesecore.core.ejb.ca.crl;

import java.util.Collection;

import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;


/** Session bean generating CRLs
 * 
 * @version $Id$
 */
public interface CrlSession {

    /**
     * Requests for a CRL to be created with the passed (revoked) certificates. 
     * Generates the CRL and stores it in the database.
     *
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param certs collection of RevokedCertInfo object.
     * @param basecrlnumber the CRL number of the Base CRL to generate a deltaCRL, -1 to generate a full CRL
     * @return The newly created CRL in DER encoded byte form or null, use CertTools.getCRLfromByteArray to convert to X509CRL.
     * @throws CATokenOfflineException 
     */
    public byte[] createCRL(Admin admin, CA ca, Collection<RevokedCertInfo> certs, int basecrlnumber) throws CATokenOfflineException;

    /**
     * Retrieves the latest CRL issued by this CA.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            the CRL issuers DN (CAs subject DN)
     * @param deltaCRL
     *            true to get the latest deltaCRL, false to get the
     *            latestcomplete CRL
     * @return byte[] with DER encoded X509CRL or null of no CRLs have been
     *         issued.
     */
    public byte[] getLastCRL(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, boolean deltaCRL);

    /**
     * Retrieves the information about the lastest CRL issued by this CA.
     * Retreives less information than getLastCRL, i.e. not the actual CRL data.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            the CRL issuers DN (CAs subject DN)
     * @param deltaCRL
     *            true to get the latest deltaCRL, false to get the
     *            latestcomplete CRL
     * @return CRLInfo of last CRL by CA or null if no CRL exists.
     */
    public org.ejbca.core.model.ca.store.CRLInfo getLastCRLInfo(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, boolean deltaCRL);

    /**
     * Retrieves the information about the specified CRL. Retreives less
     * information than getLastCRL, i.e. not the actual CRL data.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param fingerprint
     *            fingerprint of the CRL
     * @return CRLInfo of CRL or null if no CRL exists.
     */
    public org.ejbca.core.model.ca.store.CRLInfo getCRLInfo(org.ejbca.core.model.log.Admin admin, java.lang.String fingerprint);

    /**
     * Retrieves the highest CRLNumber issued by the CA.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerdn
     *            the subjectDN of a CA certificate
     * @param deltaCRL
     *            true to get the latest deltaCRL, false to get the latest
     *            complete CRL
     */
    public int getLastCRLNumber(org.ejbca.core.model.log.Admin admin, java.lang.String issuerdn, boolean deltaCRL);

}
