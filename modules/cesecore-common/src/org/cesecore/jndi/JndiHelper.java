/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.jndi;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

/**
 * The sole purpose of this class is to standardize mapping in JNDI of our Stateless Session Beans.
 * 
 * Use like this:
 * <at>Stateless(mappedName=(JndiConstants.APP_JNDI_PREFIX + RemoteInterfaceClass.class.getSimpleName()))
 * 
 */
public abstract class JndiHelper {

	private static final Logger log = Logger.getLogger(JndiHelper.class);
	
	private static Context context = null;

	
	private static Context getContext() throws NamingException {
		if (context == null) {
		    context = new InitialContext();
		}
		return context;
	}
	
	/**
	 * Helper method to get a reference to a Remote SSB interface.
	 * 
	 * Example usage: CAAdminSessionRemote caadminsession = JndiHelper.getRemoteSession(CAAdminSessionRemote.class);
	 * 
	 * @param <T>
     * @param module the module where the bean is deployed, i.e. ejbca-ejb or systemtests-ejb.
	 * @param remoteInterface
	 * @return Reference to remote SSB
	 */
	public static <T> T getRemoteSession(final Class<T> remoteInterface, final String module) {
		// JEE6, JBoss 7
	    final String viewClassName = remoteInterface.getName();
	    // Get the remote interface class, GlobalConfigurationSessionRemote, and return GlobalConfigurationSessionBean
	    // This works when we follow our own naming standard
	    final String beanName = remoteInterface.getSimpleName().replace("Remote", "Bean");
        final String jndiName = "ejb:ejbca" + "/" + module + "//"  + beanName + "!" + viewClassName;
        T ret = null;
        try {
            try {
                ret = remoteInterface.cast(getContext().lookup(jndiName));
            } catch (NamingException e) {
                // Log the original error, i.e. e not ne
                log.error("JNDI name lookup error", e);

            }           
        } catch (ClassCastException e) {
            log.error("JNDI object " + jndiName + " is not of type " + remoteInterface.getName());
        }        
		return ret;
	}
}
