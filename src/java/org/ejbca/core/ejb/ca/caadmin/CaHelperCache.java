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
package org.ejbca.core.ejb.ca.caadmin;

import java.util.HashMap;
import java.util.Map;


/**
 * Class Holding cache variables. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it only holds variables actually, does nothing. All updating etc is done by the user.
 * 
 * @version $Id$
 */
public final class CaHelperCache {

    /**
     * help variable used to control that CA info update (read from database)
     * isn't performed to often.
     */
    protected static volatile long lastCACacheUpdateTime = -1;

    /**
     * Caching of CA IDs with CA cert hash as ID
     */
    protected static volatile Map<Integer, Integer> caCertToCaId = new HashMap<Integer, Integer>();


	private CaHelperCache() {
		// Do nothing
	}

}
