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
package org.cesecore.applicationserver;

import javax.ejb.Remote;

/**
 * This bean exists for the sole purpose of verifying that transactional timeouts work as expected on different application servers.
 * 
 * @version $Id$
 * 
 */
@Remote
public interface TransactionTimeoutSessionRemote {

    /**
     * This method, when implemented, should time out after a short amount of time.
     * @param sleepTime Time that this method should sleep. 
     * 
     * @throws InterruptedException 
     */
    public int timeout(long sleepTime) throws InterruptedException;

}
