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
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.ExternalOCSPPublisher;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.ca.publisher.PublisherQueueData;
import org.ejbca.core.model.ca.publisher.PublisherQueueVolatileData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.CertTools;


/**
 * Handles management of Publishers.
 *
 * @ejb.bean description="Session bean handling interface with publisher data"
 *   display-name="PublisherSessionSB"
 *   name="PublisherSession"
 *   jndi-name="PublisherSession"
 *   local-jndi-name="PublisherSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 *
 * @ejb.ejb-external-ref description="The Publisher entity bean"
 *   view-type="local"
 *   ref-name="ejb/PublisherDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.publisher.PublisherDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.PublisherDataLocal"
 *   link="PublisherData"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref description="The publisher queue"
 *   view-type="local"
 *   ref-name="ejb/PublisherQueueSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal"
 *   link="PublisherQueueSession"
 *   
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.publisher.IPublisherSessionRemote"
 *
 *  @jonas.bean ejb-name="PublisherSession"
 */
public class LocalPublisherSessionBean extends BaseSessionBean {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /**
     * The local home interface of publisher entity bean.
     */
    private PublisherDataLocalHome publisherhome = null;

    /**
     * The local interface of authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

    /**
     * Local interface to the publisher queue, that handles failed publishings.
     */
    private IPublisherQueueSessionLocal pubqueuesession = null;
    
    /**
     * The remote interface of  log session bean
     */
    private ILogSessionLocal logsession = null;


    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        publisherhome = (PublisherDataLocalHome) getLocator().getLocalHome(PublisherDataLocalHome.COMP_NAME);
    }


    /**
     * Gets connection to log session bean
     *
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession


    /**
     * Gets connection to authorization session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = authorizationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession

    /**
     * Gets connection to publisher queue session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IPublisherQueueSessionLocal getPublisherQueueSession() {
        if (pubqueuesession == null) {
            try {
            	IPublisherQueueSessionLocalHome pqhome = (IPublisherQueueSessionLocalHome) getLocator().getLocalHome(IPublisherQueueSessionLocalHome.COMP_NAME);
                pubqueuesession = pqhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return pubqueuesession;
    } //getPublisherQueueSession

    /**
     * Stores the certificate to the given collection of publishers.
     * See BasePublisher class for further documentation about function
     *
     * @param publisherids a Collection (Integer) of publisherids.
     * @return true if sucessfull result on all given publishers
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(Admin admin, Collection publisherids, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) {
    	return storeCertificate(admin, LogConstants.EVENT_INFO_STORECERTIFICATE, LogConstants.EVENT_ERROR_STORECERTIFICATE, publisherids, incert, username, password, userDN, cafp, status, type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation);
    }

    /**
     * Revokes the certificate in the given collection of publishers.
     * See BasePublisher class for further documentation about function
     *
     * @param publisherids a Collection (Integer) of publisherids.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void revokeCertificate(Admin admin, Collection publisherids, Certificate cert, String username, String userDN, String cafp, int type, int reason, long revocationDate, String tag, int certificateProfileId, long lastUpdate) {
    	storeCertificate(admin, LogConstants.EVENT_INFO_REVOKEDCERT, LogConstants.EVENT_ERROR_REVOKEDCERT, publisherids, cert, username, null, userDN, cafp, SecConst.CERT_REVOKED, type, revocationDate, reason, tag, certificateProfileId, lastUpdate, null);
    }


    /** The same basic method is be used for both store and revoke
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
     * @return true if publishing was successful for all publishers, false if not or if was enqued for any of the publishers
     */
    private boolean storeCertificate(Admin admin, int logInfoEvent, int logErrorEvent, Collection publisherids, Certificate cert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) {
        Iterator iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            int publishStatus = PublisherQueueData.STATUS_PENDING;
            Integer id = (Integer) iter.next();
            try {
            	PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
            	String fingerprint = CertTools.getFingerprintAsString(cert);
            	// If it should be published directly
            	if (!getPublisher(pdl).getOnlyUseQueue()) {
	            	try {
	            		if (getPublisher(pdl).storeCertificate(admin, cert, username, password, userDN, cafp, status, type, revocationDate, revocationReason, tag, certificateProfileId, lastUpdate, extendedinformation)) {
	            			publishStatus = PublisherQueueData.STATUS_SUCCESS;
	            		}
	            		String msg = intres.getLocalizedMessage("publisher.store", CertTools.getSubjectDN(cert), pdl.getName());            	
	            		getLogSession().log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
	            	} catch (PublisherException pe) {
	            		String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName(), fingerprint);            	
	            		getLogSession().log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, pe);
	            	}
            	}
            	if (publishStatus != PublisherQueueData.STATUS_SUCCESS) {
            		returnval = false;
            	}
            	if (log.isDebugEnabled()) {
                	log.debug("KeepPublishedInQueue: "+getPublisher(pdl).getKeepPublishedInQueue());
                	log.debug("UseQueueForCertificates: "+getPublisher(pdl).getUseQueueForCertificates());            		
            	}
            	if ( (publishStatus != PublisherQueueData.STATUS_SUCCESS || getPublisher(pdl).getKeepPublishedInQueue()) && getPublisher(pdl).getUseQueueForCertificates()) {
                	// Write to the publisher queue either for audit reasons or to be able try again
                	PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
                	pqvd.setUsername(username);
                	pqvd.setPassword(password);
                	pqvd.setExtendedInformation(extendedinformation);
                	pqvd.setUserDN(userDN);
                	String fp = CertTools.getFingerprintAsString(cert); 
                	try {
                   		getPublisherQueueSession().addQueueData(id.intValue(), PublisherQueueData.PUBLISH_TYPE_CERT, fp, pqvd, publishStatus);
                		String msg = intres.getLocalizedMessage("publisher.storequeue", pdl.getName(), fp, status);            	
                		getLogSession().log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logInfoEvent, msg);
                	} catch (CreateException e) {
                		String msg = intres.getLocalizedMessage("publisher.errorstorequeue", pdl.getName(), fp, status);            	
                		getLogSession().log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), username, cert, logErrorEvent, msg, e);
                	}
            	}
            } catch (FinderException fe) {
            	String msg = intres.getLocalizedMessage("publisher.nopublisher", id);            	
            	getLogSession().log(admin, cert, LogConstants.MODULE_CA, new java.util.Date(), null, cert, logErrorEvent, msg);
    			returnval = false;
            }
        }
        return returnval;
    }

    /**
     * Stores the crl to the given collection of publishers.
     * See BasePublisher class for further documentation about function
     *
     * @param publisherids a Collection (Integer) of publisherids.
     * @return true if sucessfull result on all given publishers
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCRL(Admin admin, Collection publisherids, byte[] incrl, String cafp, String userDN) {
    	log.trace(">storeCRL");
        Iterator iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            int publishStatus = PublisherQueueData.STATUS_PENDING;
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
            	// If it should be published directly
                if (!getPublisher(pdl).getOnlyUseQueue()) {
                	try {
	            		if (getPublisher(pdl).storeCRL(admin, incrl, cafp, userDN)) {
	            			publishStatus = PublisherQueueData.STATUS_SUCCESS;
	            		}
                		String msg = intres.getLocalizedMessage("publisher.store", "CRL", pdl.getName());            	
                		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
                	} catch (PublisherException pe) {
                		String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName(), "CRL");            	
                		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg, pe);
                	}
                }
            	if (publishStatus != PublisherQueueData.STATUS_SUCCESS) {
            		returnval = false;
            	}
            	if (log.isDebugEnabled()) {
                	log.debug("KeepPublishedInQueue: "+getPublisher(pdl).getKeepPublishedInQueue());
                	log.debug("UseQueueForCRLs: "+getPublisher(pdl).getUseQueueForCRLs());            		
            	}
            	if ( (publishStatus != PublisherQueueData.STATUS_SUCCESS || getPublisher(pdl).getKeepPublishedInQueue()) && getPublisher(pdl).getUseQueueForCRLs()) {
                	// Write to the publisher queue either for audit reasons or to be able try again
                	final PublisherQueueVolatileData pqvd = new PublisherQueueVolatileData();
                	pqvd.setUserDN(userDN);
            		String fp = CertTools.getFingerprintAsString(incrl); 
            		try {
            			getPublisherQueueSession().addQueueData(id.intValue(), PublisherQueueData.PUBLISH_TYPE_CRL, fp, pqvd, PublisherQueueData.STATUS_PENDING);
                		String msg = intres.getLocalizedMessage("publisher.storequeue", pdl.getName(), fp, "CRL");            	
                		getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECRL, msg);
            		} catch (CreateException e) {
            			String msg = intres.getLocalizedMessage("publisher.errorstorequeue", pdl.getName(), fp, "CRL");            	
            			getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg, e);
            		}
            	}
            } catch (FinderException fe) {
            	String msg = intres.getLocalizedMessage("publisher.nopublisher", id);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECRL, msg);
    			returnval = false;
            }
        }
    	log.trace("<storeCRL");
        return returnval;
    }

    /**
     * Test the connection to of a publisher
     *
     * @param publisherid the id of the publisher to test.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException {
    	if (log.isTraceEnabled()) {
            log.trace(">testConnection(id: " + publisherid + ")");
    	}
        try {
            PublisherDataLocal pdl = publisherhome.findByPrimaryKey(new Integer(publisherid));
            String name = pdl.getName();
            try {
                getPublisher(pdl).testConnection(admin);
            	String msg = intres.getLocalizedMessage("publisher.testedpublisher", name);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherConnectionException pe) {
            	String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg, pe);
                throw new PublisherConnectionException(pe.getMessage());
            }
        } catch (FinderException fe) {
        	String msg = intres.getLocalizedMessage("publisher.nopublisher", new Integer(publisherid));            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);

        }
    	if (log.isTraceEnabled()) {
            trace("<testConnection(id: " + publisherid + ")");
    	}
    }

    /**
     * Adds a publisher to the database.
     *
     * @throws PublisherExistsException if hard token already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ")");
    	}
        addPublisher(admin,findFreePublisherId().intValue(),name,publisher);
        trace("<addPublisher()");
    } // addPublisher


    /**
     * Adds a publisher to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">addPublisher(name: " + name + ", id: " + id + ")");
    	}
        boolean success = false;
        try {
            publisherhome.findByName(name);
        } catch (FinderException e) {
            try {
                publisherhome.findByPrimaryKey(new Integer(id));
            } catch (FinderException f) {
                try {
                    publisherhome.create(new Integer(id), name, publisher);
                    success = true;
                } catch (CreateException g) {
                	String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);            	
                    error(msg, g);
                }
            }
        }
        if (success) {
        	String msg = intres.getLocalizedMessage("publisher.addedpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        if (!success) {
            throw new PublisherExistsException();
        }
        log.trace("<addPublisher()");
    } // addPublisher

    /**
     * Updates publisher data
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void changePublisher(Admin admin, String name, BasePublisher publisher) {
    	if (log.isTraceEnabled()) {
            log.trace(">changePublisher(name: " + name + ")");
    	}
        boolean success = false;
        try {
            PublisherDataLocal htp = publisherhome.findByName(name);
            htp.setPublisher(publisher);
            success = true;
        } catch (FinderException e) {
        }

        if (success) {
        	String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
        }

        trace("<changePublisher()");
    } // changePublisher

    /**
     * Adds a publisher with the same content as the original.
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void clonePublisher(Admin admin, String oldname, String newname) {
    	if (log.isTraceEnabled()) {
            log.trace(">clonePublisher(name: " + oldname + ")");
    	}
        BasePublisher publisherdata = null;
        try {
            PublisherDataLocal htp = publisherhome.findByName(oldname);
            publisherdata = (BasePublisher) getPublisher(htp).clone();
            try {
                addPublisher(admin, newname, publisherdata);
            	String msg = intres.getLocalizedMessage("publisher.clonedpublisher", newname, oldname);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherExistsException f) {
            	String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);            	
                getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
                throw f;
            }
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);            	
            error(msg, e);
            throw new EJBException(e);
        }
        log.trace("<clonePublisher()");
    } // clonePublisher

    /**
     * Removes a publisher from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void removePublisher(Admin admin, String name) {
    	if (log.isTraceEnabled()) {
            log.trace(">removePublisher(name: " + name + ")");
    	}
        try {
            PublisherDataLocal htp = publisherhome.findByName(name);
            htp.remove();
        	String msg = intres.getLocalizedMessage("publisher.removedpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("publisher.errorremovepublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg, e);
        }
        log.trace("<removePublisher()");
    } // removePublisher

    /**
     * Renames a publisher
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException {
    	if (log.isTraceEnabled()) {
            log.trace(">renamePublisher(from " + oldname + " to " + newname + ")");
    	}
        boolean success = false;
        try {
            publisherhome.findByName(newname);
        } catch (FinderException e) {
            try {
                PublisherDataLocal htp = publisherhome.findByName(oldname);
                htp.setName(newname);
                success = true;
            } catch (FinderException g) {
            }
        }

        if (success) {
        	String msg = intres.getLocalizedMessage("publisher.renamedpublisher", oldname, newname);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldname, newname);            	
            getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        if (!success) {
            throw new PublisherExistsException();
        }
        log.trace("<renamePublisher()");
    } // renameHardTokenProfile

    /**
     * Retrives a Collection of id:s (Integer) for all authorized publishers if the Admin has the SUPERADMIN role.
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any administrator.
     *
     * @param admin Should be an Admin with superadmin credentials
     * @return Collection of id:s (Integer)
     * @throws AuthorizationDeniedException if the admin does not have superadmin credentials
     * @ejb.interface-method view-type="both"
     */
    public Collection getAllPublisherIds(Admin admin) throws AuthorizationDeniedException {
        HashSet returnval = new HashSet();
        try {
            getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
            Collection allPublishers = this.publisherhome.findAll();
            Iterator i = allPublishers.iterator();
            while (i.hasNext()) {
                PublisherDataLocal next = (PublisherDataLocal) i.next();
                returnval.add(next.getId());
            }
        } catch (FinderException fe) {
        	log.error("FinderException looking for all publishers: ", fe);
        }
        return returnval;
    }

    /**
     * Method creating a hashmap mapping publisher id (Integer) to publisher name (String).
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public HashMap getPublisherIdToNameMap(Admin admin) {
        HashMap returnval = new HashMap();
        Collection result = null;

        try {
            result = publisherhome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
                PublisherDataLocal next = (PublisherDataLocal) i.next();
                returnval.put(next.getId(), next.getName());
            }
        } catch (FinderException e) {
        }
        return returnval;
    } // getPublisherIdToNameMap


    /**
     * Retrives a named publisher.
     *
     * @return a BasePublisher or null of a publisher with the given id does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BasePublisher getPublisher(Admin admin, String name) {
        BasePublisher returnval = null;

        try {
            returnval = getPublisher(publisherhome.findByName(name));
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } //  getPublisher

    /**
     * Finds a publisher by id.
     *
     * @return a BasePublisher or null of a publisher with the given id does not exist
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BasePublisher getPublisher(Admin admin, int id) {
        BasePublisher returnval = null;

        try {
            returnval = getPublisher(publisherhome.findByPrimaryKey(new Integer(id)));
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } // getPublisher

    /**
     * Help method used by publisher proxys to indicate if it is time to
     * update it's data.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public int getPublisherUpdateCount(Admin admin, int publisherid) {
        int returnval = 0;

        try {
            returnval = (publisherhome.findByPrimaryKey(new Integer(publisherid))).getUpdateCounter();
        } catch (FinderException e) {
        }

        return returnval;
    }


    /**
     * Returns a publisher id, given it's publishers name
     *
     * @return the id or 0 if the publisher cannot be found.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public int getPublisherId(Admin admin, String name) {
        int returnval = 0;

        try {
            Integer id = (publisherhome.findByName(name)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    } // getPublisherId

    /**
     * Returns a publishers name given its id.
     *
     * @return the name or null if id doesnt exists
     * @throws EJBException if a communication or other error occurs.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public String getPublisherName(Admin admin, int id) {
    	if (log.isTraceEnabled()) {
            log.trace(">getPublisherName(id: " + id + ")");
    	}
        String returnval = null;
        PublisherDataLocal htp = null;
        try {
            htp = publisherhome.findByPrimaryKey(new Integer(id));
            if (htp != null) {
                returnval = htp.getName();
            }
        } catch (FinderException e) {
        }
        log.trace("<getPublisherName()");
        return returnval;
    } // getPublisherName

    /**
     * Use from Healtcheck only! Test connection for all publishers. No authorization checks are performed.
     *
     * @return an error message or an empty String if all are ok.
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="local"
     */
    public String testAllConnections() {
        log.trace(">testAllPublishers");
        String returnval = "";
        Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
		try {
			Collection allPublishers = this.publisherhome.findAll();;
			Iterator i = allPublishers.iterator();
			while (i.hasNext()) {
				PublisherDataLocal pdl = (PublisherDataLocal) i.next();
				String name = pdl.getName();
				try {
					getPublisher(pdl).testConnection(admin);
				} catch (PublisherConnectionException pe) {
					String msg = intres.getLocalizedMessage("publisher.errortestpublisher", name);            	
					getLogSession().log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_PUBLISHERDATA, msg, pe);
					returnval +="\n" + msg;
				}
			}
		} catch (FinderException e) {
			returnval += "Could not access publishers.";
		}
        log.trace("<testAllPublishers");
        return returnval;
    }

    private Integer findFreePublisherId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1) {
                    publisherhome.findByPrimaryKey(new Integer(id));
                }
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreePublisherId

    /**
     * Method that returns the publisher data and updates it if necessary.
     */
    private BasePublisher getPublisher(PublisherDataLocal pData) {
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
    		case LdapPublisher.TYPE_LDAPPUBLISHER:
    			publisher = new LdapPublisher();
    			break;
    		case LdapSearchPublisher.TYPE_LDAPSEARCHPUBLISHER:
    			publisher = new LdapSearchPublisher();
    			break;
    		case ActiveDirectoryPublisher.TYPE_ADPUBLISHER:
    			publisher = new ActiveDirectoryPublisher();
    			break;
    		case CustomPublisherContainer.TYPE_CUSTOMPUBLISHERCONTAINER:
    			publisher = new CustomPublisherContainer();
    			break;
    		case ExternalOCSPPublisher.TYPE_EXTOCSPPUBLISHER:
    			publisher = new ExternalOCSPPublisher();
    			break;
    		}
    		publisher.loadData(data);
    	}
    	return publisher;
    }


} // LocalPublisherSessionBean
