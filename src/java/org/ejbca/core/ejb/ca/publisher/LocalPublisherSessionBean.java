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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
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
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.ExtendedInformation;


/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
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
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
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
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
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
    private InternalResources intres = InternalResources.getInstance();
    
    /**
     * The local home interface of publisher entity bean.
     */
    private PublisherDataLocalHome publisherhome = null;

    /**
     * The local interface of ca admin session bean
     */
    private ICAAdminSessionLocal caadminsession = null;

    /**
     * The local interface of authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

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
     * Gets connection to caadmin session bean
     *
     * @return ICAAdminSessionLocal
     */
    private ICAAdminSessionLocal getCAAdminSession() {
        if (caadminsession == null) {
            try {
                ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caadminsession = caadminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return caadminsession;
    } //getCAAdminSession


    /**
     * Stores the certificate to the given collection of publishers.
     * See BasePublisher class for further documentation about function
     *
     * @param publisherids a Collection (Integer) of publisherids.
     * @return true if sucessfull result on all given publishers
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(Admin admin, Collection publisherids, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, ExtendedInformation extendedinformation) {
        Iterator iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
                try {
                    returnval &= pdl.getPublisher().storeCertificate(admin, incert, username, password, cafp, status, type, revocationDate, revocationReason, extendedinformation);
                	String msg = intres.getLocalizedMessage("publisher.store", ((X509Certificate) incert).getSubjectDN().toString(), pdl.getName());            	
                    getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username,
                            (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE, msg);
                } catch (PublisherException pe) {
                	String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName());            	
                    getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert,
                            LogEntry.EVENT_ERROR_STORECERTIFICATE, msg, pe);

                }
            } catch (FinderException fe) {
            	String msg = intres.getLocalizedMessage("publisher.nopublisher", id);            	
                getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert,
                        LogEntry.EVENT_ERROR_STORECERTIFICATE, msg);

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
    public boolean storeCRL(Admin admin, Collection publisherids, byte[] incrl, String cafp, int number) {
        Iterator iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
                try {
                    returnval &= pdl.getPublisher().storeCRL(admin, incrl, cafp, number);
                	String msg = intres.getLocalizedMessage("publisher.store", "CRL", pdl.getName());            	
                    getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null,
                            null, LogEntry.EVENT_INFO_STORECRL, msg);
                } catch (PublisherException pe) {
                	String msg = intres.getLocalizedMessage("publisher.errorstorecert", pdl.getName());            	
                    getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                            LogEntry.EVENT_ERROR_STORECRL, msg, pe);

                }
            } catch (FinderException fe) {
            	String msg = intres.getLocalizedMessage("publisher.nopublisher", id);            	
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_STORECRL, msg);

            }
        }

        return returnval;
    }

    /**
     * Revokes the certificate in the given collection of publishers.
     * See BasePublisher class for further documentation about function
     *
     * @param publisherids a Collection (Integer) of publisherids.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void revokeCertificate(Admin admin, Collection publisherids, Certificate cert, int reason) {
        Iterator iter = publisherids.iterator();
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
                try {
                    pdl.getPublisher().revokeCertificate(admin, cert, reason);
                	String msg = intres.getLocalizedMessage("publisher.store", ((X509Certificate) cert).getSubjectDN().toString(), pdl.getName());            	
                    getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null,
                            (X509Certificate) cert, LogEntry.EVENT_INFO_REVOKEDCERT, msg);
                } catch (PublisherException pe) {
                	String msg = intres.getLocalizedMessage("publisher.errorstore", pdl.getName());            	
                    getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) cert,
                            LogEntry.EVENT_ERROR_REVOKEDCERT, msg, pe);

                }
            } catch (FinderException fe) {
            	String msg = intres.getLocalizedMessage("publisher.nopublisher", id);            	
                getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) cert,
                        LogEntry.EVENT_ERROR_REVOKEDCERT, msg);

            }
        }
    }

    /**
     * Test the connection to of a publisher
     *
     * @param publisherid the id of the publisher to test.
     * @ejb.interface-method view-type="both"
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException {
        debug(">testConnection(id: " + publisherid + ")");
        try {
            PublisherDataLocal pdl = publisherhome.findByPrimaryKey(new Integer(publisherid));
            try {
                pdl.getPublisher().testConnection(admin);
            	String msg = intres.getLocalizedMessage("publisher.testedpublisher", pdl.getName());            	
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null,
                        null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherConnectionException pe) {
            	String msg = intres.getLocalizedMessage("publisher.errortestpublisher", pdl.getName());            	
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_PUBLISHERDATA, msg, pe);

                throw new PublisherConnectionException(pe.getMessage());
            }
        } catch (FinderException fe) {
        	String msg = intres.getLocalizedMessage("publisher.nopublisher", Integer.valueOf(publisherid));            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_PUBLISHERDATA, msg);

        }
        debug("<testConnection(id: " + publisherid + ")");
    }

    /**
     * Adds a publisher to the database.
     *
     * @throws PublisherExistsException if hard token already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException {
        debug(">addPublisher(name: " + name + ")");
        addPublisher(admin,findFreePublisherId().intValue(),name,publisher);
        debug("<addPublisher()");
    } // addPublisher


    /**
     * Adds a publisher to the database.
     * Used for importing and exporting profiles from xml-files.
     *
     * @throws PublisherExistsException if hard token already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException {
        debug(">addPublisher(name: " + name + ", id: " + id + ")");
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
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.erroraddpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        if (!success)
            throw new PublisherExistsException();
        debug("<addPublisher()");
    } // addPublisher

    /**
     * Updates publisher data
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */

    public void changePublisher(Admin admin, String name, BasePublisher publisher) {
        debug(">changePublisher(name: " + name + ")");
        boolean success = false;
        try {
            PublisherDataLocal htp = publisherhome.findByName(name);
            htp.setPublisher(publisher);
            success = true;
        } catch (FinderException e) {
        }

        if (success) {
        	String msg = intres.getLocalizedMessage("publisher.changedpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.errorchangepublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, msg);
        }

        debug("<changePublisher()");
    } // changePublisher

    /**
     * Adds a publisher with the same content as the original.
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void clonePublisher(Admin admin, String oldname, String newname) {
        debug(">clonePublisher(name: " + oldname + ")");
        BasePublisher publisherdata = null;
        try {
            PublisherDataLocal htp = publisherhome.findByName(oldname);
            publisherdata = (BasePublisher) htp.getPublisher().clone();
            try {
                addPublisher(admin, newname, publisherdata);
            	String msg = intres.getLocalizedMessage("publisher.clonedpublisher", newname, oldname);            	
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
            } catch (PublisherExistsException f) {
            	String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);            	
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, msg);
                throw f;
            }
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("publisher.errorclonepublisher", newname, oldname);            	
            error(msg, e);
            throw new EJBException(e);
        }

        debug("<clonePublisher()");
    } // clonePublisher

    /**
     * Removes a publisher from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void removePublisher(Admin admin, String name) {
        debug(">removePublisher(name: " + name + ")");
        try {
            PublisherDataLocal htp = publisherhome.findByName(name);
            htp.remove();
        	String msg = intres.getLocalizedMessage("publisher.removedpublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("publisher.errorremovepublisher", name);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, msg, e);
        }
        debug("<removePublisher()");
    } // removePublisher

    /**
     * Renames a publisher
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException {
        debug(">renamePublisher(from " + oldname + " to " + newname + ")");
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
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, msg);
        } else {
        	String msg = intres.getLocalizedMessage("publisher.errorrenamepublisher", oldname, newname);            	
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, msg);
        }
        if (!success)
            throw new PublisherExistsException();
        debug("<renamePublisher()");
    } // renameHardTokenProfile

    /**
     * Retrives a Collection of id:s (Integer) to authorized publishers.
     *
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedPublisherIds(Admin admin) {
        HashSet returnval = new HashSet();
        Collection result = null;
        boolean superadmin = false;
        // If superadmin return all available publishers
        try {
            superadmin = getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
            result = this.publisherhome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
                PublisherDataLocal next = (PublisherDataLocal) i.next();
                returnval.add(next.getId());
            }
        } catch (AuthorizationDeniedException e1) {
        	log.debug("AuthorizationDeniedException: ", e1);
        } catch (FinderException fe) {
        	log.error("FinderException looking for all publishers: ", fe);
        }

        // If CA-admin return publishers he is authorized to 
        if (!superadmin) {
            Iterator authorizedcas = this.getAuthorizationSession().getAuthorizedCAIds(admin).iterator();
            while (authorizedcas.hasNext()) {
                returnval.addAll(this.getCAAdminSession().getCAInfo(admin, ((Integer) authorizedcas.next()).intValue()).getCRLPublishers());
            }
        }
        return returnval;
    } // getAuthorizedPublisherIds

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
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BasePublisher getPublisher(Admin admin, String name) {
        BasePublisher returnval = null;

        try {
            returnval = (publisherhome.findByName(name)).getPublisher();
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } //  getPublisher

    /**
     * Finds a publisher by id.
     *
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public BasePublisher getPublisher(Admin admin, int id) {
        BasePublisher returnval = null;

        try {
            returnval = (publisherhome.findByPrimaryKey(new Integer(id))).getPublisher();
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
        debug(">getPublisherName(id: " + id + ")");
        String returnval = null;
        PublisherDataLocal htp = null;
        try {
            htp = publisherhome.findByPrimaryKey(new Integer(id));
            if (htp != null) {
                returnval = htp.getName();
            }
        } catch (FinderException e) {
        }

        debug("<getPublisherName()");
        return returnval;
    } // getPublisherName


    private Integer findFreePublisherId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1)
                    publisherhome.findByPrimaryKey(new Integer(id));
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreePublisherId


} // LocalPublisherSessionBean
