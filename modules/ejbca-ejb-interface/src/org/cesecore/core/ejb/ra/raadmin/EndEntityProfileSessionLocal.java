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
package org.cesecore.core.ejb.ra.raadmin;

import javax.ejb.Local;

/**
 * @version $Id$
 */
@Local
public interface EndEntityProfileSessionLocal extends EndEntityProfileSession {

	/** Add the next Timer timeout when the profile cache should be updated. */
	void addCacheTimer();

	/** Called from the timer service to update the profile cache if needed. */
	void flushProfileCacheIfNeeded();
}
