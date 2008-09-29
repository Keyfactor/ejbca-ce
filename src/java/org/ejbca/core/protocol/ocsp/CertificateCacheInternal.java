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
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;


/**
 * Class managing a cache of Certificates. This class should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @version $Id$
 * 
 */
public class CertificateCacheInternal extends CertificateCache {
	
    /** Log4j instance for Base */
    private static final Logger log = Logger.getLogger(CertificateCacheInternal.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**  
     * @param prop Properties giving initialization parameters. Required parameters are ocspSigningCertsValidTime and ocspResponderType.
     * prop can be set to null to use default values 0 and OCSPUtil.RESPONDER_TYPE_INTERNAL. 
     */
    public CertificateCacheInternal(Properties prop) {
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
    	return getStoreSession().findCertificatesByType(adm, type, issuerDN);    		
    }

    private ICertificateStoreSessionLocal m_certStore = null;
    private synchronized ICertificateStoreSessionLocal getStoreSession(){
    	if(m_certStore == null){	
    		try {
    			ICertificateStoreSessionLocalHome storehome = (ICertificateStoreSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    			m_certStore = storehome.create();
    		}catch(Exception e){
    			throw new EJBException(e);
    		}
    	}
    	return m_certStore;
    }

}
