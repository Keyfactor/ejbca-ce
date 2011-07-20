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
 * Version copied from EJBCA: 
 *      JndiHelper.java 10288 2010-10-26 11:27:21Z anatom
 * Based on CESeCore version:
 *      JndiHelper.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
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
	 * @param remoteInterface
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public static <T> T getRemoteSession(final Class<T> remoteInterface) {
		final String jndiName = JndiConstants.APP_JNDI_PREFIX + remoteInterface.getSimpleName();
		try {
			return (T) getContext().lookup(jndiName);
		} catch (ClassCastException e) {
			log.error("JNDI object " + jndiName + " is not of type " + remoteInterface.getName());
		} catch (NamingException e) {
			log.error("", e);
		}
		return null;
	}

}
