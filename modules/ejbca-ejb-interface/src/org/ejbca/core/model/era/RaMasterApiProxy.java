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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.CAInfo;
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
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        AccessSet merged = new AccessSet();
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    AccessSet as = raMasterApi.getUserAccessSet(authenticationToken);
                    merged = new AccessSet(merged, as);
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return merged;
    }
    
    @Override
    public List<AccessSet> getUserAccessSets(final List<AuthenticationToken> authenticationTokens) {
        final List<AuthenticationToken> tokens = new ArrayList<>(authenticationTokens);
        final AccessSet[] merged = new AccessSet[authenticationTokens.size()];
        for (final RaMasterApi raMasterApi : raMasterApis) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    final List<AccessSet> accessSets = raMasterApi.getUserAccessSets(tokens);
                    for (int i = 0; i < accessSets.size(); i++) {
                        if (merged[i] == null) {
                            merged[i] = accessSets.get(i);
                        } else {
                            merged[i] = new AccessSet(accessSets.get(i), merged[i]);
                        }
                    }
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        return Arrays.asList(merged);
    }

    @Override
    public List<CAInfo> getAuthorizedCas(final AuthenticationToken authenticationToken) {
        final Set<CAInfo> caInfos = new HashSet<>();
        for (final RaMasterApi raMasterApi : raMasterApisLocalFirst) {
            if (raMasterApi.isBackendAvailable()) {
                try {
                    caInfos.addAll(raMasterApi.getAuthorizedCas(authenticationToken));
                } catch (UnsupportedOperationException | RaMasterBackendUnavailableException e) {
                    // Just try next implementation
                }
            }
        }
        // Remove duplicates (which would happen in the non-production like use case where there is a peer connection over localhost
        // Note that if we ever implement .equals and .hashCode for CAInfo this could be removed
        final ArrayList<CAInfo> ret = new ArrayList<>();
        for (final CAInfo caInfo : caInfos) {
            boolean skip = false;
            for (final CAInfo caInfo2 : ret) {
                if (caInfo2.getCAId()==caInfo.getCAId()) {
                    // Skip object with same CA Id
                    skip = true;
                    break;
                }
            }
            if (!skip) {
                ret.add(caInfo);
            }
        }
        return ret;
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
