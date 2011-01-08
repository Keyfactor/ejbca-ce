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
package org.ejbca.core.protocol.crlstore;

import org.cesecore.core.ejb.ca.crl.CrlSessionStandAlone;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
/**
 * DB store of data to be used by the CA
 *
 * @author primelars
 * @version $Id$
 *
 */
abstract class CRLStoreBase implements ICRLStore {
    /**
     * Returns the certificate data only session bean
     */
    abstract CrlSessionStandAlone getCRLStore();
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getCRLInfo(org.ejbca.core.model.log.Admin, java.lang.String)
	 */
	public CRLInfo getCRLInfo(Admin admin, String fingerprint) {
		return getCRLStore().getCRLInfo(admin, fingerprint);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRL(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLStore().getLastCRL(admin, issuerdn, deltaCRL);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRLInfo(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLStore().getLastCRLInfo(admin, issuerdn, deltaCRL);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.ICRLStore#getLastCRLNumber(org.ejbca.core.model.log.Admin, java.lang.String, boolean)
	 */
	public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
		return getCRLStore().getLastCRLNumber(admin, issuerdn, deltaCRL);
	}
}
