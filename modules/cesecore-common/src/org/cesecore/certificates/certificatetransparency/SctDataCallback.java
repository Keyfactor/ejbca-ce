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

import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * Provides access to methods in SctDataSession from non-EJB modules
 *
 * @version $Id$
 */
public interface SctDataCallback {
    void saveSctData(String fingerprint, int logId, long certificateExpirationDate, String data);

    Map<Integer, byte[]> findSctData(String fingerprint);

    ExecutorService getThreadPool();
}
