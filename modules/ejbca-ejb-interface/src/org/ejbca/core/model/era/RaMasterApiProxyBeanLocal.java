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
package org.ejbca.core.model.era;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Interface for EJB access to the RaMasterApi proxy singleton
 *
 * @version $Id$
 */
@Local
public interface RaMasterApiProxyBeanLocal extends RaMasterApi {

    /**
     *
     * @param apiType the implementation of RaMasterApi to check for
     * @return returns true if an API of a certain type is available
     */
    boolean isBackendAvailable(Class<? extends RaMasterApi> apiType);

    /**
     * De-prioritizes the local RA Master API implementation, causing it to not be called if a remote connection is available.
     * Used in tests, to test "remote" peer connections to localhost.
     */
    void deferLocalForTest();

    /** @return a RaCertificateSearchResponse from a search with a given username */
    RaCertificateSearchResponse searchForCertificatesByUsername(final AuthenticationToken authenticationToken, final String username);
}
