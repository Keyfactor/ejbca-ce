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

import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;


/** Session bean generating CRLs
 * 
 * @version $Id$
 */
public interface CrlSessionStandAlone {

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
	public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL);

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
	public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL);

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
	public CRLInfo getCRLInfo(Admin admin, String fingerprint);

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
	public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL);
}
