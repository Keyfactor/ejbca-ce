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
package org.cesecore.certificates.certificatetransparency;

import java.util.concurrent.ExecutorService;

import jakarta.ejb.Local;

/**
 * @version $Id$
 */
@Local
public interface SctDataSessionLocal extends SctDataSession {

    /** Adds data to the persistent SCT cache */
    public void addSctData(SctData sctData);
    
    /** Returns a thread pool, whose threads can safely call the addSctData and fetchSctData methods */
    public ExecutorService getThreadPool();
}
