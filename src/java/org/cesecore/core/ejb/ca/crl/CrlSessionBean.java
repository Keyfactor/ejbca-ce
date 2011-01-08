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

import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs.
 * CRLs are signed using RSASignSessionBean.
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CrlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlSessionBean extends CrlSessionBeanBase implements CrlSessionLocal, CrlSessionRemote{

	static final private Logger log = Logger.getLogger(CrlSessionBean.class);
	@PersistenceContext(unitName="ejbca") EntityManager entityManager;

	@EJB LogSessionLocal logSession;

	/**
	 * Stores a CRL
	 *
	 * @param incrl  The DER coded CRL to be stored.
	 * @param cafp   Fingerprint (hex) of the CAs certificate.
	 * @param number CRL number.
	 * @param issuerDN the issuer of the CRL
	 * @param thisUpdate when this CRL was created
	 * @param nextUpdate when this CRL expires
	 * @param deltaCRLIndicator -1 for a normal CRL and 1 for a deltaCRL
	 * @return true if storage was successful.
	 */
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number, String issuerDN, Date thisUpdate, Date nextUpdate, int deltaCRLIndicator) {
		if (log.isTraceEnabled()) {
			log.trace(">storeCRL(" + cafp + ", " + number + ")");
		}
		try {
			boolean deltaCRL = deltaCRLIndicator > 0;
			int lastNo = getLastCRLNumber(admin, issuerDN, deltaCRL);
			if (number <= lastNo) {
				// There is already a CRL with this number, or a later one stored. Don't create duplicates
				String msg = intres.getLocalizedMessage("store.storecrlwrongnumber", new Integer(number), new Integer(lastNo));            	
				this.logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);        		
			}
			this.entityManager.persist(new CRLData(incrl, number, issuerDN, thisUpdate, nextUpdate, cafp, deltaCRLIndicator));
			String msg = intres.getLocalizedMessage("store.storecrl", Integer.valueOf(number), null);            	
			this.logSession.log(admin, issuerDN.toString().hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.storecrl");            	
			this.logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);
			throw new EJBException(e);
		}
		if (log.isTraceEnabled()) {
			log.trace("<storeCRL()");
		}
		return true;
	}

	/* (non-Javadoc)
	 * @see org.cesecore.core.ejb.ca.crl.CrlSessionBeanBase#getEntityManager()
	 */
	@Override
	EntityManager getEntityManager() {
		return this.entityManager;
	}

	/* (non-Javadoc)
	 * @see org.cesecore.core.ejb.ca.crl.CrlSessionBeanBase#log(org.ejbca.core.model.log.Admin, int, int, java.util.Date, java.lang.String, java.security.cert.Certificate, int, java.lang.String)
	 */
	@Override
	void log(Admin admin, int hashCode, int moduleCa, Date date,
	         String string, Certificate cert, int eventInfoGetlastcrl, String msg) {
		this.logSession.log(admin, hashCode, moduleCa, date, string, cert, eventInfoGetlastcrl, msg);
	}

}
