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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;

/**
 * TODO: Implement with proper methods. Keep in mind that there is latency, so batch things.
 * 
 * @version $Id$
 */
public interface RaMasterApi {

    boolean isBackendAvailable();

    String testCall(AuthenticationToken authenticationToken, String argument1, int argument2) throws AuthorizationDeniedException, EjbcaException;

    String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;

    String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException;


}
