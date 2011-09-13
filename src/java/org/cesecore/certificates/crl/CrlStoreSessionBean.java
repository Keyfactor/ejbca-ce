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

import java.security.cert.X509CRL;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs. CRLs are signed using
 * RSASignSessionBean.
 * 
 * Based on EJBCA version: CrlSessionBean.java 11143 2011-01-11 15:32:31Z jeklund
 * 
 * 
 * @version $Id: CrlStoreSessionBean.java 897 2011-06-20 11:17:25Z johane $
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CrlStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlStoreSessionBean implements CrlStoreSessionLocal, CrlStoreSessionRemote {

    private static final Logger log = Logger.getLogger(CrlStoreSessionBean.class);

    /** Internal localization of logs and errors */
    protected static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    public void storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String issuerDN, Date thisUpdate, Date nextUpdate,
            int deltaCRLIndicator) throws CrlStoreException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL(" + cafp + ", " + number + ")");
        }
        // Check that user is authorized to the CA that issued this CRL
        String bcdn = CertTools.stringToBCDNString(issuerDN);
        int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);

        try {
            boolean deltaCRL = deltaCRLIndicator > 0;
            int lastNo = getLastCRLNumber(issuerDN, deltaCRL);
            if (number <= lastNo) {
                // There is already a CRL with this number, or a later one stored. Don't create duplicates
                String msg = intres.getLocalizedMessage("store.errorstorecrlwrongnumber", new Integer(number), new Integer(lastNo), issuerDN);
                throw new CrlStoreException(msg);
            }
            CRLData data = new CRLData(incrl, number, issuerDN, thisUpdate, nextUpdate, cafp, deltaCRLIndicator);
            this.entityManager.persist(data);
            String msg = intres.getLocalizedMessage("store.storecrl", Integer.valueOf(number), data.getFingerprint(), data.getIssuerDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CRL_STORED, EventStatus.SUCCESS, ModuleTypes.CRL, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("store.errorstorecrl", Integer.valueOf(number), issuerDN);
            log.error(msg, e);
            throw new CrlStoreException(e); // will rollback etc
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCRL()");
        }
    }


    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public byte[] getLastCRL(String issuerdn, boolean deltaCRL) {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCRL(" + issuerdn + ", " + deltaCRL + ")");
        }
        int maxnumber = 0;
        try {
            maxnumber = getLastCRLNumber(issuerdn, deltaCRL);
            X509CRL crl = null;
            final CRLData data = CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerdn, maxnumber);
            if (data != null) {
                crl = data.getCRL();
                if (crl != null) {
                    final String msg = intres.getLocalizedMessage("store.getcrl", issuerdn, Integer.valueOf(maxnumber));
                    log.info(msg);
                    return crl.getEncoded();
                }
            }
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn);
            log.info(msg);
            throw new EJBException(e);
        }
        final String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, new Integer(maxnumber));
        log.info(msg);
        if (log.isTraceEnabled()) {
            log.trace("<getLastCRL()");
        }
        return null;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getLastCRLInfo(String issuerdn, boolean deltaCRL) {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCRLInfo(" + issuerdn + ", " + deltaCRL + ")");
        }
        int crlnumber = 0;
        try {
            crlnumber = getLastCRLNumber(issuerdn, deltaCRL);
            CRLInfo crlinfo = null;
            final CRLData data = CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerdn, crlnumber);
            if (data != null) {
                crlinfo = new CRLInfo(data.getIssuerDN(), crlnumber, data.getThisUpdate(), data.getNextUpdate());
            } else {
                if (deltaCRL && (crlnumber == 0)) {
                    if (log.isDebugEnabled()) {
                        log.debug("No delta CRL exists for CA with dn '" + issuerdn + "'");
                    }
                } else if (crlnumber == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("No CRL exists for CA with dn '" + issuerdn + "'");
                    }
                } else {
                    final String msg = intres.getLocalizedMessage("store.errorgetcrl", issuerdn, Integer.valueOf(crlnumber));
                    log.error(msg);
                }
            }
            if (log.isTraceEnabled()) {
                log.trace("<getLastCRLInfo()");
            }
            return crlinfo;
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", issuerdn);
            log.info(msg);
            throw new EJBException(e);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getCRLInfo(String fingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">getCRLInfo(" + fingerprint + ")");
        }
        try {
            CRLInfo crlinfo = null;
            final CRLData data = CRLData.findByFingerprint(entityManager, fingerprint);
            if (data != null) {
                crlinfo = new CRLInfo(data.getIssuerDN(), data.getCrlNumber(), data.getThisUpdate(), data.getNextUpdate());
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("No CRL exists with fingerprint '" + fingerprint + "'");
                }
                final String msg = intres.getLocalizedMessage("store.errorgetcrl", fingerprint, new Integer(0));
                log.info(msg);
            }
            if (log.isTraceEnabled()) {
                log.trace("<getCRLInfo()");
            }
            return crlinfo;
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("store.errorgetcrlinfo", fingerprint);
            log.info(msg);
            throw new EJBException(e);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getLastCRLNumber(String issuerdn, boolean deltaCRL) {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCRLNumber(" + issuerdn + ", " + deltaCRL + ")");
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

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCRL(final AuthenticationToken admin, final String fingerprint) throws AuthorizationDeniedException {
        final CRLData crld = CRLData.findByFingerprint(entityManager, fingerprint);
        if (crld == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a CRL that does not exist: " + fingerprint);
            }
        } else {
            // Check that user is authorized to the CA that issued this CRL
            int caid = crld.getIssuerDN().hashCode();
            authorizedToCA(admin, caid);

            entityManager.remove(crld);
            final String msg = intres.getLocalizedMessage("store.removedcrl", fingerprint, crld.getCrlNumber(), crld.getIssuerDN());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CRL_DELETED, EventStatus.SUCCESS, ModuleTypes.CRL, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), null, null, details);
        }
    }

    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }

}
