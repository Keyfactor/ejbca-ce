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
package org.ejbca.core.ejb.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CACacheManager;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.catoken.CATokenManager;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.util.CertTools;

/**
 * Implementation of CaSession, i.e takes care of all CA related CRUD
 * operations.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CaSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CaSessionBean implements CaSessionLocal, CaSessionRemote {

    private static final Logger log = Logger.getLogger(CaSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private LogSessionLocal logSession;

    @Override
    public void flushCACache() {
    	CaHelperCache.lastCACacheUpdateTime = -1;
        CACacheManager.instance().removeAll();
        if (log.isDebugEnabled()) {
            log.debug("Flushed CA cache.");
        }
    }

    @Override
    public CA getCA(Admin admin, int caid) throws CADoesntExistsException {
        if (!authorizedToCA(admin, caid)) {
            if (log.isDebugEnabled()) {
                log.debug("Admin (" + admin.toString() + ") is not authorized to CA: " + caid);
            }
            String msg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
            throw new CADoesntExistsException(msg);
        }
        return getCAInternal(caid, null);
    }
    
    @Override
    public CA getCA(Admin admin, String name) throws CADoesntExistsException {
        CA ca = getCAInternal(-1, name);
        if (!authorizedToCA(admin, ca.getCAId())) {
            if (log.isDebugEnabled()) {
                log.debug("Admin (" + admin.toString() + ") is not authorized to CA with name: " + name);
            }
            String msg = intres.getLocalizedMessage("caadmin.canotexistsid", name);
            throw new CADoesntExistsException(msg);
        }
        return ca;
    }

    @Override
    public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException {
        // check authorization
        if (!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremoveca", new Integer(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    msg);
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA from database
        try {
            CAData cadata = CAData.findByIdOrThrow(entityManager, Integer.valueOf(caid));
            // Remove CA
            entityManager.remove(cadata);
            // Invalidate CA cache to refresh information
            CACacheManager.instance().removeCA(caid);
            // Remove an eventual CA token from the token registry
            CATokenManager.instance().addCAToken(caid, null);
            String msg = intres.getLocalizedMessage("caadmin.removedca", new Integer(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("caadmin.errorremoveca", new Integer(caid), e.getMessage());
            log.error(msg, e);
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException {
        // Get CA from database
        CAData cadata = CAData.findByName(entityManager, oldname);
        if (cadata == null) {
            String msg = intres.getLocalizedMessage("caadmin.errorrenameca", oldname);
            log.error(msg);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CAEDITED, msg);
            throw new EJBException(msg);
        }
        // Check authorization
        int caid = cadata.getCaId().intValue();
        if (!authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenameca", Integer.valueOf(caid));
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_NOTAUTHORIZEDTORESOURCE,
                    msg);
            throw new AuthorizationDeniedException(msg);
        }
        CAData cadatanew = CAData.findByName(entityManager, newname);
        if (cadatanew != null) {
            cadatanew.getCaId();
            throw new CAExistsException(" CA name " + newname + " already exists.");
        } else {
            // new CA doesn't exits, it's ok to rename old one.
            cadata.setName(newname);
            // Invalidate CA cache to refresh information
            CACacheManager.instance().removeCA(cadata.getCaId().intValue());
            String msg = intres.getLocalizedMessage("caadmin.renamedca", oldname, newname);
            logSession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CAEDITED, msg);
        }
    }

    /**
     * Internal method for getting CA, to avoid code duplication. Tries to find
     * the CA even if the CAId is wrong due to CA certificate DN not being the
     * same as CA DN. Uses CACacheManager directly if configured to do so in
     * ejbca.properties.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for,
     *            or -1 of a name is to ge used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1,
     *            can be null of caid != -1
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if no CA was found
     */
    private CA getCAInternal(int caid, String name) throws CADoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">getCAInternal: " + caid + ", " + name);
        }
        // First check if we already have a cached instance of the CA
        // This should only be done if we have enabled caching, meaning that
        // we will not update the CA values until cache time expires
        CA ca = null;
        if (CaHelperCache.lastCACacheUpdateTime + EjbcaConfiguration.getCacheCaTimeInCaAdminSession() > System.currentTimeMillis()) {
            if (caid != -1) {
                ca = CACacheManager.instance().getCA(caid);
            } else {
                ca = CACacheManager.instance().getCA(name);
            }
        }
        CAData cadata = null;
        if (ca == null) {
            if (log.isDebugEnabled()) {
                log.debug("CA not found in cache (or cache time expired), we have to get it: " + caid + ", " + name);
            }
            try {
                cadata = getCADataBean(caid, name);
                // this method checks CA data row timestamp to see if CA was
                // updated by any other cluster nodes
                // also fills the CACacheManager cache if the CA is not in there
                ca = cadata.getCA();
            } catch (UnsupportedEncodingException uee) {
                throw new EJBException(uee);
            } catch (IllegalKeyStoreException e) {
                throw new EJBException(e);
            }
            CaHelperCache.lastCACacheUpdateTime = System.currentTimeMillis();
        }
        // Check if CA has expired, cadata (CA in database) will only be updated
        // if aggressive caching is not enabled
        checkCAExpireAndUpdateCA(ca, cadata);
        if (log.isTraceEnabled()) {
            log.trace("<getCAInternal: " + caid + ", " + name);
        }
        return ca;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAvailableCAs() {
        return CAData.findAllCaIds(entityManager);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAvailableCAs(Admin admin) {
        return authorizationSession.getAuthorizedCAIds(admin, getAvailableCAs());
    }
    
    /**
     * Checks if the CA certificate has expired (or is not yet valid) and sets
     * CA status to expired if it has (and status is not already expired). Logs
     * an info message that the CA certificate has expired, or is not yet valid.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param ca
     * @param cadata
     *            can be null, in which case we will try to find it in the
     *            database *if* the CA data needs to be updated
     */
    private void checkCAExpireAndUpdateCA(final CA ca, CAData cadata) {
        // Check that CA hasn't expired.
        try {
            CertTools.checkValidity(ca.getCACertificate(), new Date());
        } catch (CertificateExpiredException cee) {
            // Signers Certificate has expired, we want to make sure that the
            // status in the database is correctly EXPIRED for this CA
        	// Don't set external CAs to expired though, because they should always be treated as external CAs
        	if ( (ca.getStatus() != SecConst.CA_EXPIRED) && (ca.getStatus() != SecConst.CA_EXTERNAL) ) {
                ca.setStatus(SecConst.CA_EXPIRED); // update the value object
                // Also try to update the database with new "expired" status
                if (cadata == null) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Getting CADataBean from database to set EXPIRED status: " + ca.getCAId() + ", " + ca.getName());
                        }
                        cadata = getCADataBean(ca.getCAId(), ca.getName());
                    } catch (UnsupportedEncodingException e) {
                        // NOPMD: don't update in database if we can't find it
                    } catch (IllegalKeyStoreException e) {
                        // NOPMD: don't update in database if we can't find it
                    } catch (CADoesntExistsException e) {
                        // NOPMD: don't update in database if we can't find it
                    }
                }
                if (cadata != null) {
                    cadata.setStatus(SecConst.CA_EXPIRED);
                    cadata.setUpdateTime(new Date().getTime());
                }
            }
            String msg = intres.getLocalizedMessage("signsession.caexpired", ca.getSubjectDN());
            msg += " " + cee.getMessage();
            log.info(msg);
        } catch (CertificateNotYetValidException e) {
            // Signers Certificate is not yet valid.
            String msg = intres.getLocalizedMessage("signsession.canotyetvalid", ca.getSubjectDN());
            msg += " " + e.getMessage();
            log.warn(msg);
        }
    }

    /**
     * Internal method for getting CADataBean. Tries to find the CA even if the
     * CAId is wrong due to CA certificate DN not being the same as CA DN.
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for,
     *            or -1 of a name is to ge used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1,
     *            can be null of caid != -1
     * @throws CADoesntExistsException if no CA was found
     */
    private CAData getCADataBean(int caid, String name) throws UnsupportedEncodingException, IllegalKeyStoreException, CADoesntExistsException {
        CAData cadata = null;
        if (caid != -1) {
            cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        } else {
            cadata = CAData.findByName(entityManager, name);
        }
        if (cadata == null) {
            // We should never get to here if we are searching for name, in any
            // case if the name does not exist, the CA really does not exist
            // We don't have to try to find another mapping for the CAId
            if (caid != -1) {
                // subject DN of the CA certificate might not have all objects
                // that is the DN of the certificate data.
                final Integer oRealCAId = (Integer) CaHelperCache.caCertToCaId.get(Integer.valueOf(caid));
                // has the "real" CAID been mapped to the certificate subject
                // hash by a previous call?
                if (oRealCAId != null) {
                    // yes, using cached value of real caid.
                    cadata = CAData.findById(entityManager, oRealCAId);
                } else {
                    // no, we have to search for it among all CA certs
                    Iterator<CAData> i = CAData.findAll(entityManager).iterator();
                    while (cadata == null && i.hasNext()) {
                        final CAData tmp = i.next();
                        final Certificate caCert = tmp != null ? tmp.getCA().getCACertificate() : null;
                        if (caCert != null && caid == CertTools.getSubjectDN(caCert).hashCode()) {
                            cadata = tmp; // found. Do also cache it if
                            // someone else is needing it
                            // later
                            CaHelperCache.caCertToCaId.put(new Integer(caid), new Integer(cadata.getSubjectDN().hashCode()));
                        }
                    }
                }
            }
            if (cadata == null) {
                String msg;
                if (caid != -1) {
                    msg = intres.getLocalizedMessage("caadmin.canotexistsid", new Integer(caid));
                } else {
                    msg = intres.getLocalizedMessage("caadmin.canotexistsname", name);
                }
                log.info(msg);
                throw new CADoesntExistsException(msg);
            }
        }
        return cadata;
    }

    private boolean authorizedToCA(Admin admin, int caid) {
        return authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
    }
}
