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

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.CRLDataLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;

/**
 * 
 * An abstract base class containing common methods for workers, actions and intervals
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */

public abstract class BaseServiceComponent {
	
    private ILogSessionLocal logsession = null;
	private CertificateDataLocalHome certHome = null;
	private ICertificateStoreSessionLocal certStore = null;
	private CRLDataLocalHome crlHome = null;
	private ICAAdminSessionLocal caadminsession = null;
	private IUserAdminSessionLocal useradminsession = null;

	/**
     * return the environment entries locator
     * @return return the environment entries locator
     */
    protected ServiceLocator getLocator() {
        return ServiceLocator.getInstance();
    }
    
    /**
     * Gets connection to log session bean
     *
     * @return ILogSessionLocal
     */
    protected ILogSessionLocal getLogSession() {
        if (logsession  == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logsession ;
    } //getLogSession
    
    /**
     * Gets connection to certificate data home 
     *
     * @return CertificateDataLocalHome
     */
    protected CertificateDataLocalHome getCertificateDataHome() {
        if (certHome  == null) {
            	certHome = (CertificateDataLocalHome) getLocator().getLocalHome(CertificateDataLocalHome.COMP_NAME);
        }
        return certHome ;
    } //getCertificateDataHome

    /**
     * Gets connection to certificate store session bean
     *
     * @return CertificateDataLocalHome
     */
    protected ICertificateStoreSessionLocal getCertificateSession() {
    	if (certStore == null) {
    		try {
    			ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    			certStore = home.create();
    		} catch (CreateException e) {
    			throw new EJBException(e);
    		}        	
    	}
    	return certStore;
    } 

    /**
     * Gets connection to CRL data home 
     *
     * @return CRLDataLocalHome
     */
    protected CRLDataLocalHome getCRLDataHome() {
        if (crlHome  == null) {
            	crlHome = (CRLDataLocalHome) getLocator().getLocalHome(CRLDataLocalHome.COMP_NAME);
        }
        return crlHome ;
    } //getCRLDataHome

    /**
     * Gets connection to CA Admin session
     *
     * @return ICAAdminSessionLocal
     */
    protected ICAAdminSessionLocal getCAAdminSession() {
        if (caadminsession  == null) {
            try {
            	ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caadminsession = caadminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return caadminsession ;
    } //getCAAdminSession   
    
    /**
     * Gets connection to CA Admin session
     *
     * @return IUserAdminSessionLocal
     */
    protected IUserAdminSessionLocal getUserAdminSession() {
        if (useradminsession  == null) {
            try {
            	IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
            	useradminsession = useradminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return useradminsession ;
    } //getUserAdminSession 
    

   
}
