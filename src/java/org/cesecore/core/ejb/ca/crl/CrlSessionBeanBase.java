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
import java.security.cert.X509CRL;
import java.util.Date;

import javax.ejb.EJBException;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/** Base class with methods common to CRLSessionBean and CRLSessionStandAloneBean
 * 
 * @author lars
 * @version $Id$
 */
abstract class CrlSessionBeanBase {

	static final private Logger log = Logger.getLogger(CrlSessionBeanBase.class);

	/** Internal localization of logs and errors */
	protected static final InternalResources intres = InternalResources.getInstance();

	/** @return the Entity manager. */
	abstract EntityManager getEntityManager();

	/**
	 * Logging with log session if available
	 * @see org.cesecore.core.ejb.log.LogSessionLocal#log(Admin, Certificate, int, Date, String, Certificate, int, String)
	 */
	abstract void log(Admin admin, int hashCode, int moduleCa, Date date, String string, Certificate cert, int eventInfoGetlastcrl, String msg);

	/** @see CrlSession#getLastCRL(Admin, String, boolean) */
	protected byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRL(" + issuerdn + ", "+deltaCRL+")");
		}
		int maxnumber = 0;
		try {
			maxnumber = getLastCRLNumber(admin, issuerdn, deltaCRL);
			X509CRL crl = null;
			CRLData data = CRLData.findByIssuerDNAndCRLNumber(getEntityManager(), issuerdn, maxnumber);
			if (data != null) {
				crl = data.getCRL();
			}
			if (crl != null) {
				String msg = intres.getLocalizedMessage("store.getcrl", issuerdn, Integer.valueOf(maxnumber));            	
				log(admin, crl.getIssuerDN().toString().hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_GETLASTCRL, msg);
				return crl.getEncoded();
			}
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn);            	
			log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		}
		final String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, new Integer(maxnumber));            	
		log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
		if (log.isTraceEnabled()) {
			log.trace("<getLastCRL()");
		}
		return null;
	}

	/** @see CrlSession#getLastCRLInfo(Admin, String, boolean) */
	protected CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRLInfo(" + issuerdn + ", "+deltaCRL+")");
		}
		int crlnumber = 0;
		try {
			crlnumber = getLastCRLNumber(admin, issuerdn, deltaCRL);
			CRLInfo crlinfo = null;
			CRLData data = CRLData.findByIssuerDNAndCRLNumber(getEntityManager(), issuerdn, crlnumber);
			if (data != null) {
				crlinfo = new CRLInfo(data.getIssuerDN(), crlnumber, data.getThisUpdate(), data.getNextUpdate());
			} else {
				if (deltaCRL && (crlnumber == 0)) {
					if (log.isDebugEnabled()) {
						log.debug("No delta CRL exists for CA with dn '"+issuerdn+"'");
					}
				} else if (crlnumber == 0) {
					if (log.isDebugEnabled()) {
						log.debug("No CRL exists for CA with dn '"+issuerdn+"'");
					}
				} else {
					String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, Integer.valueOf(crlnumber));            	
					log.error(msg);            		
				}
			}
			if (log.isTraceEnabled()) {
				log.trace("<getLastCRLInfo()");
			}
			return crlinfo;
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", issuerdn);            	
			log(admin, issuerdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		}
	}

	/** @see CrlSession#getCRLInfo(Admin, String) */
	protected CRLInfo getCRLInfo(Admin admin, String fingerprint) {
		if (log.isTraceEnabled()) {
			log.trace(">getCRLInfo(" + fingerprint+")");
		}
		try {
			CRLInfo crlinfo = null;
			CRLData data = CRLData.findByFingerprint(getEntityManager(), fingerprint);
			if (data != null) {
				crlinfo = new CRLInfo(data.getIssuerDN(), data.getCrlNumber(), data.getThisUpdate(), data.getNextUpdate());
			} else {
				if (log.isDebugEnabled()) {
					log.debug("No CRL exists with fingerprint '"+fingerprint+"'");
				}
				String msg = intres.getLocalizedMessage("store.errorgetcrl", fingerprint, new Integer(0));            	
				log.error(msg);            		
			}
			if (log.isTraceEnabled()) {
				log.trace("<getCRLInfo()");
			}
			return crlinfo;
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", fingerprint);            	
			log(admin, fingerprint.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
			throw new EJBException(e);
		}
	}

	/** @see CrlSession#getLastCRLNumber(Admin, String, boolean) */
	protected int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
		if (log.isTraceEnabled()) {
			log.trace(">getLastCRLNumber(" + issuerdn + ", "+deltaCRL+")");
		}
		int maxnumber = 0;
		Integer result = CRLData.findHighestCRLNumber(getEntityManager(), issuerdn, deltaCRL);
		if (result != null) {
			maxnumber = result.intValue();
		}
		if (log.isTraceEnabled()) {
			log.trace("<getLastCRLNumber(" + maxnumber + ")");
		}
		return maxnumber;
	}
}
