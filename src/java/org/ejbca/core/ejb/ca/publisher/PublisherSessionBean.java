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

package org.ejbca.core.ejb.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;
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
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.ValidationAuthorityPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.CertTools;

/**
 * Handles management of Publishers.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "PublisherSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublisherSessionBean implements PublisherSessionLocal, PublisherSessionRemote {

    private static final Logger log = Logger.getLogger(PublisherSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private PublisherQueueSessionLocal publisherQueueSession;
    @EJB
    private LogSessionLocal logSession;

    /**
     * Stores the certificate to the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @return true if successful result on all given publishers, or if publisherids is null or empty
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(Admin admin, Collection<Integer> publisherids, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) {
        return storeCertificate(admin, LogConstants.EVENT_INFO_STORECERTIFICATE, LogConstants.EVENT_ERROR_STORECERTIFICATE, publisherids, incert, username,
                password, userDN, cafp, status, type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);
    }

    /**
     * Revokes the certificate in the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void revokeCertificate(Admin admin, Collection<Integer> publisherids, Certificate cert, String username, String userDN, String cafp, int type, int reason,
            long revocationDate, String tag, int certificateProfileId, long lastUpdate) {
        storeCertificate(admin, LogConstants.EVENT_INFO_REVOKEDCERT, LogConstants.EVENT_ERROR_REVOKEDCERT, publisherids, cert, username, null, userDN, cafp,
                SecConst.CERT_REVOKED, type, revocationDate, reason, tag, certificateProfileId, lastUpdate, null);
    }

    /**
     * The same basic method is be used for both store and revoke
     * 
     * @param admin
     * @param logInfoEvent
     * @param logErrorEvent
     * @param publisherids
     * @param cert
     * @param username
     * @param password
     * @param userDN
     * @param cafp
     * @param status
     * @param type
     * @param revocationDate
     * @param revocationReason
     * @param tag
     * @param certificateProfileId
     * @param lastUpdate
     * @param extendedinformation
     * @return true if publishing was successful for all publishers (or no publishers were given as publisherids), false if not or if was queued for any of the publishers
     */
    private boolean storeCertificate(Admin admin, int logInfoEvent, int logErrorEvent, Collection<Integer> publisherids, Certificate cert, String username,
            String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId,
            long lastUpdate, ExtendedInformation extendedinformation) {
    	if (publisherids == null) {
    		return true;
    	}
        Iterator<Integer> iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            Integer id = iter.next();
            PublisherData pdl = PublisherData.findById(entityManager, Integer.valueOf(id));
            if (pdl != null) {
                String fingerprint = CertTools.getFingerprintAsString(cert);
                // If it should be published directly
                if (!getPublisher(pdl).getOnlyUseQueue()) {
                    try {
                        if (getPublisher(pdl).storeCertificate(admin, cert, username, password, userDN, cafp, status, type, revocationDate, revocationReason,
                                tag, certificateProfileId, lastUpdate, extendedinformation)) {
                            publishStatus = PublisherConst.STATUS_SUCCESS;
                        }
                        String msg = intres.getLocalizedMessage("publisher.store", CertTools.getSubjectDN(cert), pdl.getName());
                        logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
                    } catch (PublisherException pe) {
                        String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName(), fingerprint);
                        logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, pe);
                    }
                }
                if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                    returnval = false;
                }
                if (log.isDebugEnabled()) {
                    log.debug("KeepPublishedInQueue: " + getPublisher(pdl).getKeepPublishedInQueue());
                    log.debug("UseQueueForCertificates: " + getPublisher(pdl).getUseQueueForCertificates());
                }
                if ((publishStatus != PublisherConst.STATUS_SUCCESS || getPublisher(pdl).getKeepPublishedInQueue())
                        && getPublisher(pdl).getUseQueueForCertificates()) {
                    // Write to the publisher queue either for audit reasons or
                    // to be able try again
                    PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
                    pqvd.setUsername(username);
                    pqvd.setPassword(password);
                    pqvd.setExtendedInformation(extendedinformation);
                    pqvd.setUserDN(userDN);
                    String fp = CertTools.getFingerprintAsString(cert);
                    try {
                        publisherQueueSession.addQueueData(id.intValue(), PublisherConst.PUBLISH_TYPE_CERT, fp, pqvd, publishStatus);
                        String msg = intres.getLocalizedMessage("publisher.storequeue", pdl.getName(), fp, status);
                        logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
                    } catch (CreateException e) {
                        String msg = intres.getLocalizedMessage("publisher.errorstorequeue", pdl.getName(), fp, status);
                        logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, e);
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                logSession.log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), null, cert, logErrorEvent, msg);
                returnval = false;
            }
        }
        return returnval;
    }

    /**
     * Stores the crl to the given collection of publishers. See BasePublisher
     * class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @return true if sucessfull result on all given publishers
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCRL(Admin admin, Collection<Integer> publisherids, byte[] incrl, String cafp, int number, String userDN) {
        log.trace(">storeCRL");
        Iterator<Integer> iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            int publishStatus = PublisherConst.STATUS_PENDING;
            Integer id = iter.next();
            PublisherData pdl = PublisherData.findById(entityManager, Integer.valueOf(id));
            if (pdl != null) {
                // If it should be published directly
                if (!getPublisher(pdl).getOnlyUseQueue()) {
                    try {
                        if (getPublisher(pdl).storeCRL(admin, incrl, cafp, number, userDN)) {
                            publishStatus = PublisherConst.STATUS_SUCCESS;
                        }
                        String msg = intres.getLocalizedMessage("publisher.store", "CRL", pdl.getName());
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
                    } catch (PublisherException pe) {
                        String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName(), "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL,
                                msg, pe);
                    }
                }
                if (publishStatus != PublisherConst.STATUS_SUCCESS) {
                    returnval = false;
                }
                if (log.isDebugEnabled()) {
                    log.debug("KeepPublishedInQueue: " + getPublisher(pdl).getKeepPublishedInQueue());
                    log.debug("UseQueueForCRLs: " + getPublisher(pdl).getUseQueueForCRLs());
                }
                if ((publishStatus != PublisherConst.STATUS_SUCCESS || getPublisher(pdl).getKeepPublishedInQueue())
                        && getPublisher(pdl).getUseQueueForCRLs()) {
                    // Write to the publisher queue either for audit reasons or
                    // to be able try again
                    final PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
                    pqvd.setUserDN(userDN);
                    String fp = CertTools.getFingerprintAsString(incrl);
                    try {
                        publisherQueueSession.addQueueData(id.intValue(), PublisherConst.PUBLISH_TYPE_CRL, fp, pqvd, PublisherConst.STATUS_PENDING);
                        String msg = intres.getLocalizedMessage("publisher.storequeue", pdl.getName(), fp, "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
                    } catch (CreateException e) {
                        String msg = intres.getLocalizedMessage("publisher.errorstorequeue", pdl.getName(), fp, "CRL");
                        logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL,
                                msg, e);
                    }
                }
            } else {
                String msg = intres.getLocalizedMessage("publisher.nopublisher", id);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);
                returnval = false;
            }
        }
        log.trace("<storeCRL");
        return returnval;
    }

    /**
     * Test the connection to of a publisher
     * 
     * @param publisherid
     *            the id of the publisher to test.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException {
        if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + publisherid + ")");
        }
        PublisherData pdl = PublisherData.findById(entityManager, Integer.valueOf(publisherid));
        if (pdl != null) {
            String name = pdl.getName();
            try {
                getPublisher(pdl).testConnection(admin);
                String msg = intres.getLocalizedMessage("publisher.testedpublisher", name);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherConnectionException pe) {
                String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg,
                        pe);
                throw new PublisherConnectionException(pe.getMessage());
            }
        } else {
            String msg = intres.getLocalizedMessage("publisher.nopublisher", Integer.valueOf(publisherid));
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);

        }
        if (log.isTraceEnabled()) {
            log.trace("<testConnection(id: " + publisherid + ")");
        }
    }

    /**
     * Adds a publisher to the database.
     * 
     * @throws PublisherExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ")");
        }
        addPublisher(admin, findFreePublisherId().intValue(), name, publisher);
        log.trace("<addPublisher()");
    }

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws PublisherExistsException if publisher already exists.
     */
    public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ", id: " + id + ")");
        }
        boolean success = false;
        if (PublisherData.findByName(entityManager, name) == null) {
            if (PublisherData.findById(entityManager, Integer.valueOf(id)) == null) {
                try {
                	entityManager.persist(new PublisherData(Integer.valueOf(id), name, publisher));
                    success = true;
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);
                    log.error(msg, e);
                }
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("publisher.addedpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
            throw new PublisherExistsException();
        }
        log.trace("<addPublisher()");
    }

    /**
     * Updates publisher data
     */
    public void changePublisher(Admin admin, String name, BasePublisher publisher) {
        if (log.isTraceEnabled()) {
            log.trace(">changePublisher(name: " + name + ")");
        }
        PublisherData htp = PublisherData.findByName(entityManager, name);
        if (htp != null) {
            htp.setPublisher(publisher);
            String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        log.trace("<changePublisher()");
    }

    /**
     * Adds a publisher with the same content as the original.
     * 
     * @throws PublisherExistsException
     *             if publisher already exists.
     * @throws EJBException if a communication or other error occurs.
     */
    public void clonePublisher(Admin admin, String oldname, String newname) {
        if (log.isTraceEnabled()) {
            log.trace(">clonePublisher(name: " + oldname + ")");
        }
        BasePublisher publisherdata = null;
        try {
        	PublisherData htp = PublisherData.findByName(entityManager, oldname);
        	if (htp == null) {
        		throw new Exception("Could not find publisher " + oldname);
        	}
            publisherdata = (BasePublisher) getPublisher(htp).clone();
            try {
                addPublisher(admin, newname, publisherdata);
                String msg = intres.getLocalizedMessage("publisher.clonedpublisher", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherExistsException f) {
                String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
                throw f;
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);
            log.error(msg, e);
            throw new EJBException(e);	// TODO: This might be a bit too much...
        }
        log.trace("<clonePublisher()");
    }

    /**
     * Removes a publisher from the database.
     */
    public void removePublisher(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">removePublisher(name: " + name + ")");
        }
        try {
            PublisherData htp = PublisherData.findByName(entityManager, name);
            entityManager.remove(htp);
            String msg = intres.getLocalizedMessage("publisher.removedpublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorremovepublisher", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg, e);
        }
        log.trace("<removePublisher()");
    }

    /**
     * Renames a publisher
     * 
     * @throws PublisherExistsException
     *             if publisher already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renamePublisher(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        if (PublisherData.findByName(entityManager, newname) == null) {
        	PublisherData htp = PublisherData.findByName(entityManager, oldname);
        	if (htp != null) {
                htp.setName(newname);
                success = true;
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("publisher.renamedpublisher", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
            throw new PublisherExistsException();
        }
        log.trace("<renamePublisher()");
    }

    /**
     * Retrieves a Collection of id:s (Integer) for all authorized publishers if
     * the Admin has the SUPERADMIN role.
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @param admin
     *            Should be an Admin with superadmin credentials
     * @return Collection of id:s (Integer)
     * @throws AuthorizationDeniedException
     *             if the admin does not have superadmin credentials
     */
    public Collection<Integer> getAllPublisherIds(Admin admin) throws AuthorizationDeniedException {
        HashSet<Integer> returnval = new HashSet<Integer>();
        if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR, null);
        }
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	returnval.add(i.next().getId());
        }
        return returnval;
    }

    /**
     * Method creating a hashmap mapping publisher id (Integer) to publisher
     * name (String).
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public HashMap<Integer,String> getPublisherIdToNameMap(Admin admin) {
        HashMap<Integer,String> returnval = new HashMap<Integer,String>();
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	PublisherData next = i.next();
        	returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    /**
     * Retrives a named publisher.
     * 
     * @return a BasePublisher or null of a publisher with the given id does not
     *         exist
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public BasePublisher getPublisher(Admin admin, String name) {
        BasePublisher returnval = null;
        PublisherData pd = PublisherData.findByName(entityManager, name);
        if (pd != null) {
        	returnval = getPublisher(pd);
        }
        return returnval;
    }

    /**
     * Finds a publisher by id.
     * 
     * @return a BasePublisher or null of a publisher with the given id does not
     *         exist
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public BasePublisher getPublisher(Admin admin, int id) {
        BasePublisher returnval = null;
        PublisherData pd = PublisherData.findById(entityManager, Integer.valueOf(id));
        if (pd != null) {
        	returnval = getPublisher(pd);
        }
        return returnval;
    }

    /**
     * Help method used by publisher proxys to indicate if it is time to update
     * it's data.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getPublisherUpdateCount(Admin admin, int publisherid) {
        int returnval = 0;
        PublisherData pd = PublisherData.findById(entityManager, Integer.valueOf(publisherid));
        if (pd != null) {
        	returnval = pd.getUpdateCounter();
        }
        return returnval;
    }

    /**
     * Returns a publisher id, given it's publishers name
     * 
     * @return the id or 0 if the publisher cannot be found.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getPublisherId(Admin admin, String name) {
        int returnval = 0;
        PublisherData pd = PublisherData.findByName(entityManager, name);
        if (pd != null) {
        	returnval = pd.getId();
        }
        return returnval;
    }

    /**
     * Returns a publishers name given its id.
     * 
     * @return the name or null if id doesn't exists
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public String getPublisherName(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublisherName(id: " + id + ")");
        }
        String returnval = null;
        PublisherData pd = PublisherData.findById(entityManager, Integer.valueOf(id));
        if (pd != null) {
        	returnval = pd.getName();
        }
        log.trace("<getPublisherName()");
        return returnval;
    }

    /**
     * Use from Healtcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * 
     * @return an error message or an empty String if all are ok.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public String testAllConnections() {
        log.trace(">testAllPublishers");
        String returnval = "";
        Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
        Iterator<PublisherData> i = PublisherData.findAll(entityManager).iterator();
        while (i.hasNext()) {
        	PublisherData pdl = i.next();
        	String name = pdl.getName();
        	try {
        		getPublisher(pdl).testConnection(admin);
        	} catch (PublisherConnectionException pe) {
        		String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);
        		logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA,
        				msg, pe);
        		returnval += "\n" + msg;
        	}
        }
        log.trace("<testAllPublishers");
        return returnval;
    }

    private Integer findFreePublisherId() {
    	Random ran = (new Random((new Date()).getTime()));
    	int id = ran.nextInt();
    	boolean foundfree = false;
    	while (!foundfree) {
    		if (id > 1) {
    			PublisherData pd = PublisherData.findById(entityManager, Integer.valueOf(id));
    			if (pd == null) {
    				foundfree = true;
    			}
    		}
    		id = ran.nextInt();
    	}
    	return Integer.valueOf(id);
    }

    /**
     * Method that returns the publisher data and updates it if necessary.
     */
    private BasePublisher getPublisher(PublisherData pData) {
        BasePublisher publisher = pData.getCachedPublisher();
        if (publisher == null) {
            java.beans.XMLDecoder decoder;
            try {
                decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(pData.getData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }
            HashMap h = (HashMap) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values
            HashMap data = new Base64GetHashMap(h);

            switch (((Integer) (data.get(BasePublisher.TYPE))).intValue()) {
            case PublisherConst.TYPE_LDAPPUBLISHER:
                publisher = new LdapPublisher();
                break;
            case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                publisher = new LdapSearchPublisher();
                break;
            case PublisherConst.TYPE_ADPUBLISHER:
                publisher = new ActiveDirectoryPublisher();
                break;
            case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                publisher = new CustomPublisherContainer();
                break;
            case PublisherConst.TYPE_VAPUBLISHER:
                publisher = new ValidationAuthorityPublisher();
                break;
            }
            publisher.loadData(data);
        }
        return publisher;
    }
}
