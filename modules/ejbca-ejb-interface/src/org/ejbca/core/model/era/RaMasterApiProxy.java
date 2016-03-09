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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.EjbcaException;

/**
 * Proxy implementation of the the RaMasterApi that will will get the result of the most preferred API implementation
 * or a mix thereof depending of the type of call.
 * 
 * @version $Id$
 */
public class RaMasterApiProxy implements RaMasterApi {
    
    private static final Logger log = Logger.getLogger(RaMasterApiProxy.class);
    private final RaMasterApi[] raMasterApis;
    private final RaMasterApi[] raMasterApisLocalFirst;
    
    public RaMasterApiProxy(final RaMasterApi...raMasterApis) {
        if (raMasterApis.length==0) {
            final List<RaMasterApi> implementations = new ArrayList<>();
            try {
                // Load peer implementation if available in this version of EJBCA
                final Class<?> c = Class.forName("org.ejbca.peerconnector.ra.RaMasterApiPeerImpl");
                implementations.add((RaMasterApi) c.newInstance());
            } catch (ClassNotFoundException e) {
                log.debug("RaMasterApi over Peers is not available on this system.");
            } catch (InstantiationException | IllegalAccessException e) {
                log.warn("Failed to instantiate RaMasterApi over Peers: " + e.getMessage());
            }
            implementations.add(new RaMasterApiLocalImpl());
            this.raMasterApis = implementations.toArray(new RaMasterApi[implementations.size()]);
            Collections.reverse(implementations);
            this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
        } else {
            this.raMasterApis = raMasterApis;
            final List<RaMasterApi> implementations = new ArrayList<RaMasterApi>(Arrays.asList(raMasterApis));
            Collections.reverse(implementations);
            this.raMasterApisLocalFirst = implementations.toArray(new RaMasterApi[implementations.size()]);
        }
    }

    @Override
    public boolean isBackendAvailable() {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String testCall(AuthenticationToken authenticationToken, String argument1, int argument2) throws AuthorizationDeniedException, EjbcaException {
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.testCall(authenticationToken, argument1, argument2);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        throw new RaMasterBackendUnavailableException();
    }

    @Override
    public String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    return raMasterApi.testCallPreferLocal(authenticationToken, requestData);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        throw new RaMasterBackendUnavailableException();
    }

    @Override
    public List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        final List<String> ret = new ArrayList<>();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final List<String> result = raMasterApi.testCallMerge(authenticationToken, requestData);
                    if (result!=null) {
                        ret.addAll(result);
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return ret;
    }

    @Override
    public String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        // TODO: Ask module cache, module is responsible for getting bulk of info from master if needed
        return "cached value";
    }
}
