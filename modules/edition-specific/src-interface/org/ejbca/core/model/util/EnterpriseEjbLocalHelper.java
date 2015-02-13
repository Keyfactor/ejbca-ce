/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.util;

import java.util.concurrent.locks.ReentrantLock;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id: EjbLocalHelper.java 19968 2014-10-09 13:13:58Z mikekushner $
 */
public class EnterpriseEjbLocalHelper implements EnterpriseEditionEjbBridgeSessionLocal {
    
    private static final Logger log = Logger.getLogger(EnterpriseEjbLocalHelper.class);
    private static Context initialContext = null;
    private static ReentrantLock initialContextLock = new ReentrantLock(true);
    // Static is more performant, but a failed JEE5 lookup from one module would block all other JEE5 lookups
    private /*static*/ boolean useEjb31GlobalJndiName = false;
    
    private Context getInitialContext() throws NamingException {
        try {
            initialContextLock.lock();
            if (initialContext == null) {
                initialContext = new InitialContext();
            }
            return initialContext;
        } finally {
            initialContextLock.unlock();
        }
    }
    
       /**
     * Requires a "ejb-local-ref" definition in web.xml and ejb-jar.xml from all accessing components
     * or an application server that support global JNDI names (introduced in EJB 3.1).
     * @return a reference to the bridge SSB
     * 
     * @throws LocalLookupException if local lookup couldn't be made.
     */
    private EnterpriseEditionEjbBridgeSessionLocal getEnterpriseEditionEjbLocal() {
        EnterpriseEditionEjbBridgeSessionLocal ret = null;
        try {
            if (!useEjb31GlobalJndiName) {
                ret = (EnterpriseEditionEjbBridgeSessionLocal) getInitialContext().lookup("java:comp/env/EnterpriseEditionEjbBridgeSession");
            }
        } catch (NamingException e) {
            // Let's try to use the EJB 3.1 syntax for a lookup. For example, JBoss 6.0.0.FINAL supports this from our CMP TCP threads, but ignores the ejb-ref from web.xml..
            // java:global[/<app-name>]/<module-name>/<bean-name>[!<fully-qualified-interface-name>]
            useEjb31GlobalJndiName = true;  // So let's not try what we now know is a failing method ever again..
            if (log.isDebugEnabled()) {
                log.debug("Failed JEE5 version of EnterpriseEditionEjbBridgeSessionLocal JNDI lookup. All future lookups will JEE6 version lookups.");
            }
        }
        try {
            if (useEjb31GlobalJndiName) {
                ret = (EnterpriseEditionEjbBridgeSessionLocal) getInitialContext().lookup("java:global/ejbca/peerconnector-ejb/EnterpriseEditionEjbBridgeSessionBean!org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal");
            }
        } catch (NamingException e) {
            throw new LocalLookupException("Cannot lookup EnterpriseEditionEjbBridgeSessionLocal.", e);
        }
        return ret;
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T getEnterpriseEditionEjbLocal(final Class<T> localInterfaceClass, final String modulename) {
        try {
            // Try JEE6 lookup first
            return (T) getInitialContext().lookup("java:global/ejbca/"+modulename+"/"+localInterfaceClass.getSimpleName().replaceAll("Local", "Bean") + "!"+localInterfaceClass.getName());
        } catch (NamingException e) {
            return getEnterpriseEditionEjbLocal().getEnterpriseEditionEjbLocal(localInterfaceClass, null);
        }
    }
}
