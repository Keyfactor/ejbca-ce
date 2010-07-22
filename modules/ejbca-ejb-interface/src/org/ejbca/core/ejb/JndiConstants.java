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


/**
 * The sole purpose of this class is to standardize mapping in JNDI of our Stateless Session Beans.
 * 
 * Use like this:
 * <at>Stateless(mappedName=(JndiConstants.APP_JNDI_PREFIX + RemoteInterfaceClass.class.getSimpleName()))
 * 
 * @version $Id$
 */
public abstract class JndiConstants {
	
	public static final String APP_JNDI_PREFIX = "ejbca/";
	
}
