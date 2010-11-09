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

import org.cesecore.core.ejb.log.LogSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
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
     * Gets connection to log session bean
     *
     * @return ILogSessionLocal
     */
    protected LogSession getLogSession() {
        if (logSession  == null) {
            	logSession = new EjbLocalHelper().getLogSession();
 
        }
        return logSession ;
    } //getLogSession
    
    /**
     * Gets connection to certificate store session bean
     *
     * @return CertificateDataLocalHome
     */
    protected CertificateStoreSession getCertificateSession() {
    	if (certificateStoreSession == null) {
    	
    			certificateStoreSession = new EjbLocalHelper().getCertStoreSession();
    	       	
    	}
    	return certificateStoreSession;
    } 


    /**
     * Gets connection to CA Admin session
     *
     * @return ICAAdminSessionLocal
     */
    protected CAAdminSession getCAAdminSession() {
        if (caAdminSession  == null) {

            	caAdminSession = new EjbLocalHelper().getCAAdminSession();
         
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
      
            	userAdminSession = new EjbLocalHelper().getUserAdminSession();
       
        }
        return userAdminSession ;
    } //getUserAdminSession 
    
    protected PublisherQueueSession getPublisherQueueSession() {
        if (publisherQueueSession  == null) {

            	publisherQueueSession = new EjbLocalHelper().getPublisherQueueSession();
         
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
