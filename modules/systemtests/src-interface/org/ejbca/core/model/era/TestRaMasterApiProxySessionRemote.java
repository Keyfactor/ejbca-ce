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
package org.ejbca.core.model.era;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;

/**
 * @version $Id$
 *
 */
@Remote
public interface TestRaMasterApiProxySessionRemote {

    /**
     * Dispatch CMP request over RaMasterApi.
     * 
     * Basic ASN.1 validation is performed at a proxy to increase the protection of a CA slightly.
     * 
     * Will use a local AlwaysAllowToken, which should fail if used remotely. 
     * 
     * @param authenticationToken the origin of the request
     * @param pkiMessageBytes the ASN.1 encoded CMP message request bytes
     * @param cmpConfigurationAlias the requested CA configuration that should handle the request.
     * @return the CMP response ASN.1 (success or error) message as a byte array or null if no processing could take place
     * @see CmpMessageDispatcherSessionLocal#dispatchRequest(AuthenticationToken, byte[], String)
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    byte[] cmpDispatch(byte[] pkiMessageBytes, String cmpConfigurationAlias) throws NoSuchAliasException;
    
    /**
     * 
     * @param apiType the implementation of RaMasterApi to check for 
     * @return returns true if an API of a certain type is available
     */
    boolean isBackendAvailable(Class<? extends RaMasterApi> apiType);
    
}
