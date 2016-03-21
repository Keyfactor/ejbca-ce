/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

import java.util.List;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.ejbca.core.EjbcaException;

/**
 * TODO: Implement with proper methods. Keep in mind that there is latency, so batch things.
 * 
 * @version $Id$
 */
public interface RaMasterApi {

    /** @return true if the implementation if the interface is available and usable. */
    boolean isBackendAvailable();
    
    AccessSet getUserAccessSet(AuthenticationToken authenticationToken) throws AuthenticationFailedException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCall(AuthenticationToken authenticationToken, String argument1, int argument2) throws AuthorizationDeniedException, EjbcaException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    @Deprecated // PoC. Remove when we have real functions to invoke.
    String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;


}
