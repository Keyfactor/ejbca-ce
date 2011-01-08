/**
 * 
 */
package org.cesecore.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.Date;

import javax.ejb.EJBException;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * @author lars
 *
 */
abstract class CrlSessionBeanBase {

	static final private Logger log = Logger.getLogger(CrlSessionBeanBase.class);

	/** Internal localization of logs and errors */
	protected static final InternalResources intres = InternalResources.getInstance();
	/**
	 * @return the Entity manager.
	 */
	abstract EntityManager getEntityManager();
	/**
	 * Logging with log session if available
	 * @see org.cesecore.core.ejb.log.LogSessionLocal#log(Admin, Certificate, int, Date, String, Certificate, int, String)
	 */
	abstract void log(Admin admin, int hashCode, int moduleCa, Date date, String string, Certificate cert, int eventInfoGetlastcrl, String msg);
	/**
	 * Retrieves the latest CRL issued by this CA.
	 *
	 * @param admin Administrator performing the operation
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
	 * @return byte[] with DER encoded X509CRL or null of no CRLs have been issued.
	 */
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
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

	/**
	 * Retrieves the information about the lastest CRL issued by this CA. Retreives less information than getLastCRL, i.e. not the actual CRL data.
	 *
	 * @param admin Administrator performing the operation
	 * @param issuerdn the CRL issuers DN (CAs subject DN)
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latestcomplete CRL
	 * @return CRLInfo of last CRL by CA or null if no CRL exists.
	 */
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
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

	/**
	 * Retrieves the information about the specified CRL. Retreives less information than getLastCRL, i.e. not the actual CRL data.
	 *
	 * @param admin Administrator performing the operation
	 * @param fingerprint fingerprint of the CRL
	 * @return CRLInfo of CRL or null if no CRL exists.
	 */
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	public CRLInfo getCRLInfo(Admin admin, String fingerprint) {
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

	/**
	 * Retrieves the highest CRLNumber issued by the CA.
	 *
	 * @param admin    Administrator performing the operation
	 * @param issuerdn the subjectDN of a CA certificate
	 * @param deltaCRL true to get the latest deltaCRL, false to get the latest complete CRL
	 */
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
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
