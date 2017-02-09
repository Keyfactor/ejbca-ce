/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.crl;

import java.util.Date;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/** Session bean storing and retrieving CRLs
 * 
 * @version $Id$
 */
public interface CrlStoreSession {

	/**
	 * Retrieves the latest CRL issued by this CA.
	 * 
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
	 * @return byte[] with DER encoded X509CRL or null of no CRLs have been issued.
	 */
	byte[] getLastCRL(String issuerdn, boolean deltaCRL);

    /**
     * Retrieves a specific CRL issued by this CA.
     * 
     * @param issuerdn the CRL issuers DN (CAs subject DN)
     * @param crlNumber a crlNumber of a complete, or delta, CRL
     * @return byte[] with DER encoded X509CRL or null of no CRLs have been issued.
     */
    byte[] getCRL(String issuerdn, int crlNumber);

	/**
	 * Retrieves the information about the latest CRL issued by this CA.
	 * Retrieves less information than getLastCRL, i.e. not the actual CRL data.
	 * 
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
	 * @return CRLInfo of last CRL by CA or null if no CRL exists.
	 */
	CRLInfo getLastCRLInfo(String issuerdn, boolean deltaCRL);

	/**
	 * Retrieves the information about the specified CRL. Retrieves less
	 * information than getLastCRL, i.e. not the actual CRL data.
	 * 
	 * @param fingerprint fingerprint of the CRL
	 * @return CRLInfo of CRL or null if no CRL exists.
	 */
	CRLInfo getCRLInfo(String fingerprint);

	/**
	 * Retrieves the highest CRLNumber issued by the CA.
	 * 
	 * @param issuerdn the subjectDN of a CA certificate
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
	 * @return the highest CRL number of CRLs issued by issuerdn, or 0 if no CRLs were issued.
	 */
	int getLastCRLNumber(String issuerdn, boolean deltaCRL);
	
	/**
     * Stores a CRL
     *
	 * @param admin Administrator performing the operation
     * @param incrl  The DER coded CRL to be stored.
     * @param cafp   Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     * @param issuerDN the issuer of the CRL
     * @param thisUpdate when this CRL was created
     * @param nextUpdate when this CRL expires
     * @param deltaCRLIndicator -1 for a normal CRL and 1 for a deltaCRL
     * 
     * @throws CrlStoreException (rollback) if an error occured storing the CRL
     * @throws AuthorizationDeniedException (rollback) if admin was not authorized to store CRL
     */
    void storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String issuerDN, Date thisUpdate, Date nextUpdate, int deltaCRLIndicator)
    	throws CrlStoreException, AuthorizationDeniedException;
	
}
