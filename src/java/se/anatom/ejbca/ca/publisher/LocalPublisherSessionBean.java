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

package se.anatom.ejbca.ca.publisher;

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

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.exception.PublisherConnectionException;
import se.anatom.ejbca.ca.exception.PublisherException;
import se.anatom.ejbca.ca.exception.PublisherExistsException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.ExtendedInformation;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean description="Session bean handling interface with ra authorization"
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
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="java:/${datasource.jndi-name}"
 *
 * @ejb.env-entry description="Custom Available Access Rules, use ';' to separate multiple accessrules"
 *   name="CustomAvailableAccessRules"
 *   type="java.lang.String"
 *   value=""
 *
 * @ejb.ejb-ref view-type="local"
 *   ejb-name="PublisherData"
 *   ref-name="ejb/PublisherDataLocal"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ejb-name="AuthorizationSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome"
 *   business="se.anatom.ejbca.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ejb-name="CAAdminSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   business="se.anatom.ejbca.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.ca.publisher.IPublisherSessionLocalHome"
 *   remote-class="se.anatom.ejbca.ca.publisher.IPublisherSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.ca.publisher.IPublisherSessionLocal"
 *   remote-class="se.anatom.ejbca.ca.publisher.IPublisherSessionRemote"
 *
 *  @jonas.bean ejb-name="PublisherSession"
 */
public class LocalPublisherSessionBean extends BaseSessionBean {

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
     * @see se.anatom.ejbca.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(Admin admin, Collection publisherids, Certificate incert, String username, String password, String cafp, int status, int type, ExtendedInformation extendedinformation) {
        Iterator iter = publisherids.iterator();
        boolean returnval = true;
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
                try {
                    returnval &= pdl.getPublisher().storeCertificate(admin, incert, username, password, cafp, status, type, extendedinformation);
                    getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username,
                            (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,
                            "Added object: " + ((X509Certificate) incert).getSubjectDN().toString() + " successfully to publisher " + pdl.getName() + ".");
                } catch (PublisherException pe) {
                    getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert,
                            LogEntry.EVENT_ERROR_STORECERTIFICATE, "Error when publishing certificate to " + pdl.getName() + " : " + pe.getMessage());

                }
            } catch (FinderException fe) {
                getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert,
                        LogEntry.EVENT_ERROR_STORECERTIFICATE, "Publisher with id " + id + " doesn't exist.");

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
     * @see se.anatom.ejbca.ca.publisher.BasePublisher
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
                    getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null,
                            null, LogEntry.EVENT_INFO_STORECRL,
                            "Publisher CLR successfully to publisher " + pdl.getName() + ".");
                } catch (PublisherException pe) {
                    getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                            LogEntry.EVENT_ERROR_STORECRL, "Error when publishing CRL to " + pdl.getName() + " : " + pe.getMessage());

                }
            } catch (FinderException fe) {
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_STORECRL, "Publisher with id " + id + " doesn't exist.");

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
     * @see se.anatom.ejbca.ca.publisher.BasePublisher
     */
    public void revokeCertificate(Admin admin, Collection publisherids, Certificate cert, int reason) {
        Iterator iter = publisherids.iterator();
        while (iter.hasNext()) {
            Integer id = (Integer) iter.next();
            try {
                PublisherDataLocal pdl = publisherhome.findByPrimaryKey(id);
                try {
                    pdl.getPublisher().revokeCertificate(admin, cert, reason);
                    getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null,
                            (X509Certificate) cert, LogEntry.EVENT_INFO_REVOKEDCERT,
                            "Revoked certificate: " + ((X509Certificate) cert).getSubjectDN().toString() + " successfully in publisher " + pdl.getName() + ".");
                } catch (PublisherException pe) {
                    getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) cert,
                            LogEntry.EVENT_ERROR_REVOKEDCERT, "Error when revoking certificate in publisher " + pdl.getName() + " : " + pe.getMessage());

                }
            } catch (FinderException fe) {
                getLogSession().log(admin, (X509Certificate) cert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) cert,
                        LogEntry.EVENT_ERROR_REVOKEDCERT, "Publisher with id " + id + " doesn't exist.");

            }
        }
    }

    /**
     * Test the connection to of a publisher
     *
     * @param publisherid the id of the publisher to test.
     * @ejb.interface-method view-type="both"
     * @see se.anatom.ejbca.ca.publisher.BasePublisher
     */
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException {
        debug(">testConnection(id: " + publisherid + ")");
        try {
            PublisherDataLocal pdl = publisherhome.findByPrimaryKey(new Integer(publisherid));
            try {
                pdl.getPublisher().testConnection(admin);
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null,
                        null, LogEntry.EVENT_INFO_PUBLISHERDATA,
                        "Successfully tested the connection with publisher " + pdl.getName() + ".");
            } catch (PublisherConnectionException pe) {
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_PUBLISHERDATA, "Error when testing the connection with publisher " + pdl.getName() + " : " + pe.getMessage());

                throw new PublisherConnectionException(pe.getMessage());
            }
        } catch (FinderException fe) {
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_PUBLISHERDATA, "Publisher with id " + publisherid + " doesn't exist.");

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
                    error("Unexpected error creating new publisher: ", g);
                }
            }
        }
        if (success)
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, "Publisher " + name + " added.");
        else
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, "Error adding publisher " + name);
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

        if (success)
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, "Publisher " + name + " edited.");
        else
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, "Error editing publisher " + name + ".");

        debug("<changePublisher()");
    } // changePublisher

    /**
     * Adds a publisher with the same content as the original.
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws EJBException             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public void clonePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException {
        debug(">clonePublisher(name: " + oldname + ")");
        BasePublisher publisherdata = null;
        try {
            PublisherDataLocal htp = publisherhome.findByName(oldname);
            publisherdata = (BasePublisher) htp.getPublisher().clone();
            try {
                addPublisher(admin, newname, publisherdata);
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, "New publisher " + newname + ", used publisher " + oldname + " as template.");
            } catch (PublisherExistsException f) {
                getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, "Error adding publisher " + newname + " using publisher " + oldname + " as template.");
                throw f;
            }
        } catch (Exception e) {
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
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, "Publisher " + name + " removed.");
        } catch (Exception e) {
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, "Error removing publisher " + name + ".", e);
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

        if (success)
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_PUBLISHERDATA, "Publisher " + oldname + " renamed to " + newname + ".");
        else
            getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_PUBLISHERDATA, " Error renaming publisher  " + oldname + " to " + newname + ".");

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
            superadmin = getAuthorizationSession().isAuthorized(admin, AvailableAccessRules.ROLE_SUPERADMINISTRATOR);
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

        // If ca admin return
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
    } // findFreeHardTokenIssuerId


} // LocalPublisherSessionBean
