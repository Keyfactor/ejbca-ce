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

package org.ejbca.cesecoreintegration;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.time.TrustedTime;
import org.cesecore.time.TrustedTimeWatcherSessionLocal;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * This is the trusted time watcher implementation.
 * 
 *
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ServerTimeWatcherSessionBean implements TrustedTimeWatcherSessionLocal {

	@Override
	public TrustedTime getTrustedTime(final boolean force) throws TrustedTimeProviderException {
		final TrustedTime tt = new TrustedTime();
		tt.setSync(false);
		return tt;
	}


}
