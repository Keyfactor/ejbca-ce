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

package org.ejbca.core.protocol.ocsp;

import java.util.Collection;
import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreOnlyDataSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;


/**
 * Class managing a cache of Certificates. This class should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @version $Id$
 * 
 */
public class CertificateCacheStandalone extends CertificateCache {
	
    /** Log4j instance for Base */
    private static final Logger log = Logger.getLogger(CertificateCacheStandalone.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**  
     * @param prop Properties giving initialization parameters. Required parameters are ocspSigningCertsValidTime and ocspResponderType.
     * prop can be set to null to use default values 0 and OCSPUtil.RESPONDER_TYPE_INTERNAL. 
     */
    public CertificateCacheStandalone(Properties prop) {
    	super(prop);
    }
    
    /**
     * 
     * @param adm
     * @param type
     * @param issuerDN
     * @return Collection of Certificate never null
     */
    protected Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
    	return getStoreSessionOnlyData().findCertificatesByType(adm, type, issuerDN);    		
    }

    private ICertificateStoreOnlyDataSessionLocal m_certStoreOnly = null;
    private synchronized ICertificateStoreOnlyDataSessionLocal getStoreSessionOnlyData(){
    	if(m_certStoreOnly == null){	
    		try {
                ServiceLocator locator = ServiceLocator.getInstance();
                ICertificateStoreOnlyDataSessionLocalHome castorehome = (ICertificateStoreOnlyDataSessionLocalHome)locator.getLocalHome(ICertificateStoreOnlyDataSessionLocalHome.COMP_NAME);
                m_certStoreOnly = castorehome.create();
    		}catch(Exception e){
    			throw new EJBException(e);      	  	    	  	
    		}
    	}
    	return m_certStoreOnly;
    }

}
