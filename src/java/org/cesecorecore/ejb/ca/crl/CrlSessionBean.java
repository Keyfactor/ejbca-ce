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

package org.cesecorecore.ejb.ca.crl;

import java.security.cert.X509CRL;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.crl.CrlSessionLocal;
import org.cesecore.core.ejb.ca.crl.CrlSessionRemote;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.store.CRLData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.store.CRLInfo;
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
public class CrlSessionBean implements CrlSessionLocal, CrlSessionRemote{

    private static final Logger log = Logger.getLogger(CrlSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;

   
        
    

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
            	String msg = intres.getLocalizedMessage("store.storecrlwrongnumber", number, lastNo);            	
            	logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);        		
        	}
        	entityManager.persist(new CRLData(incrl, number, issuerDN, thisUpdate, nextUpdate, cafp, deltaCRLIndicator));
        	String msg = intres.getLocalizedMessage("store.storecrl", new Integer(number), null);            	
        	logSession.log(admin, issuerDN.toString().hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.storecrl");            	
            logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<storeCRL()");
    	}
        return true;
    }

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
        	CRLData data = CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerdn, maxnumber);
        	if (data != null) {
                crl = data.getCRL();
            }
            if (crl != null) {
            	String msg = intres.getLocalizedMessage("store.getcrl", issuerdn, new Integer(maxnumber));            	
                logSession.log(admin, crl.getIssuerDN().toString().hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_GETLASTCRL, msg);
                return crl.getEncoded();
            }
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
            throw new EJBException(e);
        }
    	String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, maxnumber);            	
        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
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
            CRLData data = CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerdn, crlnumber);
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
                	String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, new Integer(crlnumber));            	
                    log.error(msg);            		
            	}
                crlinfo = null;
            }
        	if (log.isTraceEnabled()) {
        		log.trace("<getLastCRLInfo()");
        	}
            return crlinfo;
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", issuerdn);            	
            logSession.log(admin, issuerdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
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
            CRLData data = CRLData.findByFingerprint(entityManager, fingerprint);
            if (data != null) {
                crlinfo = new CRLInfo(data.getIssuerDN(), data.getCrlNumber(), data.getThisUpdate(), data.getNextUpdate());
            } else {
            	if (log.isDebugEnabled()) {
            		log.debug("No CRL exists with fingerprint '"+fingerprint+"'");
            	}
            	String msg = intres.getLocalizedMessage("store.errorgetcrl", fingerprint, 0);            	
            	log.error(msg);            		
            }
        	if (log.isTraceEnabled()) {
        		log.trace("<getCRLInfo()");
        	}
            return crlinfo;
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", fingerprint);            	
            logSession.log(admin, fingerprint.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_GETLASTCRL, msg);
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
    	Integer result = CRLData.findHighestCRLNumber(entityManager, issuerdn, deltaCRL);
    	if (result != null) {
    		maxnumber = result.intValue();
    	}
    	if (log.isTraceEnabled()) {
            log.trace("<getLastCRLNumber(" + maxnumber + ")");
    	}
    	return maxnumber;
    }

}
