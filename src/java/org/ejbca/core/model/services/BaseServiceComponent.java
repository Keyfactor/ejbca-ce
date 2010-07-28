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

package org.ejbca.core.model.services;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.log.LogSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * An abstract base class containing common methods for workers, actions and intervals
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public abstract class BaseServiceComponent {

	// TODO: Find way to lookup/inject Local interfaces..
    private LogSession logSession = null;
	private CertificateStoreSession certificateStoreSession = null;
	private CAAdminSession caAdminSession = null;
	private UserAdminSession userAdminSession = null;
	private PublisherQueueSession publisherQueueSession = null;
	private PublisherSession publisherSession = null;

	/**
     * return the environment entries locator
     * @return return the environment entries locator
     */
    /*protected ServiceLocator getLocator() {
        return ServiceLocator.getInstance();
    }*/
    
    /**
     * Gets connection to log session bean
     *
     * @return ILogSessionLocal
     */
    protected LogSession getLogSession() {
        if (logSession  == null) {
            try {
                /*ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();*/
            	logSession = new EjbLocalHelper().getLogSession();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logSession ;
    } //getLogSession
    
    /**
     * Gets connection to certificate data home 
     *
     * @return CertificateDataLocalHome
     */
    /*protected CertificateDataLocalHome getCertificateDataHome() {
        if (certHome  == null) {
            	certHome = (CertificateDataLocalHome) getLocator().getLocalHome(CertificateDataLocalHome.COMP_NAME);
        }
        return certHome ;
    } //getCertificateDataHome*/

    /**
     * Gets connection to certificate store session bean
     *
     * @return CertificateDataLocalHome
     */
    protected CertificateStoreSession getCertificateSession() {
    	if (certificateStoreSession == null) {
    		try {
    			/*ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    			certStore = home.create();*/
    			certificateStoreSession = new EjbLocalHelper().getCertStoreSession();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}        	
    	}
    	return certificateStoreSession;
    } 

    /**
     * Gets connection to CRL data home 
     *
     * @return CRLDataLocalHome
     */
    /*protected CRLDataLocalHome getCRLDataHome() {
        if (crlHome  == null) {
            	crlHome = (CRLDataLocalHome) getLocator().getLocalHome(CRLDataLocalHome.COMP_NAME);
        }
        return crlHome ;
    } //getCRLDataHome*/

    /**
     * Gets connection to CA Admin session
     *
     * @return ICAAdminSessionLocal
     */
    protected CAAdminSession getCAAdminSession() {
        if (caAdminSession  == null) {
            try {
            	/*ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caadminsession = caadminsessionhome.create();*/
            	caAdminSession = new EjbLocalHelper().getCAAdminSession();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return caAdminSession ;
    } //getCAAdminSession   
    
    /**
     * Gets connection to CA Admin session
     *
     * @return IUserAdminSessionLocal
     */
    protected UserAdminSession getUserAdminSession() {
        if (userAdminSession  == null) {
            try {
            	/*IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
            	useradminsession = useradminsessionhome.create();*/
            	userAdminSession = new EjbLocalHelper().getUserAdminSession();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return userAdminSession ;
    } //getUserAdminSession 
    
    protected PublisherQueueSession getPublisherQueueSession() {
        if (publisherQueueSession  == null) {
            try {
            	/*IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
            	useradminsession = useradminsessionhome.create();*/
            	publisherQueueSession = new EjbLocalHelper().getPublisherQueueSession();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return publisherQueueSession ;
    }   
    protected PublisherSession getPublisherSession() {
        if (publisherSession  == null) {
        	publisherSession = new EjbLocalHelper().getPublisherSession();
        }
        return publisherSession ;
    }   
}
