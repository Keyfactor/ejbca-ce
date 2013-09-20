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
package org.cesecore.time;

import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * This is the trusted time watcher. It will periodically update the status of trusted time (if is synchronous, accuracy, etc).
 * The update period is self managed and is based on infromation gathered from the trusted time provider.
 * 
 * @version $Id$
 * 
 */
public interface TrustedTimeWatcherSession {


    /**
     * 
     * Retrieves the current TrustedTime instance made available in the watcher.
     * The first time this method is invoked it will update the current TrustedTime by making a direct call to 
     * the provider and it will schedule a new update interval based on information provided by ntp protocol. 
     *
     * @param force forces the TrustedTime update from the provider.
     * @return Watcher TrustedTime current instance.
     * 
     * @throws TrustedTimeProviderException
     */
    TrustedTime getTrustedTime(boolean force) throws TrustedTimeProviderException;

}
