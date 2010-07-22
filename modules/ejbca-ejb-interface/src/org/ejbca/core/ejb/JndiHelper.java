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

package org.ejbca.core.ejb;

import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

/**
 * The sole purpose of this class is to standardize mapping in JNDI of our Stateless Session Beans.
 * 
 * Use like this:
 * <at>Stateless(mappedName=(JndiConstants.APP_JNDI_PREFIX + RemoteInterfaceClass.class.getSimpleName()))
 * 
 * @version $Id$
 */
public abstract class JndiHelper {

	public static final String APP_JNDI_PREFIX = "ejbca/";

	private static final Logger log = Logger.getLogger(JndiHelper.class);

	/**
	 * Helper method to get a reference to a Remote SSB interface.
	 * 
	 * Example usage: CAAdminSessionRemote caadminsession = JndiHelper.getRemoteSession(new javax.naming.InitialContext(), CAAdminSessionRemote.class);
	 * 
	 * @param <T>
	 * @param context
	 * @param remoteInterface
	 * @return
	 */
	public static <T> T getRemoteSession(Context context, Class<T> remoteInterface) {
		String jndiName = APP_JNDI_PREFIX + remoteInterface.getSimpleName();
		try {
			return (T) context.lookup(jndiName);
		} catch (ClassCastException e) {
			log.error("JNDI object " + jndiName + " is not if type " +
					remoteInterface.getName());
		} catch (NamingException e) {
			log.error("", e);
		}
		return null;
	}


}
