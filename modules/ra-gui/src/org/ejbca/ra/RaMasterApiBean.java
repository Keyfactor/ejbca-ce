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
package org.ejbca.ra;

import java.io.Serializable;
import java.util.List;

import javax.faces.bean.ApplicationScoped;
import javax.faces.bean.ManagedBean;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.era.RaMasterApi;
import org.ejbca.core.model.era.RaMasterApiProxy;

/**
 * JSF Managed Bean for interactions with the back-end.
 * 
 * @version $Id$
 */
@ManagedBean
@ApplicationScoped
public class RaMasterApiBean implements Serializable, RaMasterApi {

    private static final long serialVersionUID = 1L;
    private RaMasterApi raMasterApi = new RaMasterApiProxy();

    public boolean isBackendAvailable() {
        return raMasterApi.isBackendAvailable();
    }
    
    @Override
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        return raMasterApi.getUserAccessSet(authenticationToken);
    }

    @Override
    public List<AccessSet> getUserAccessSets(final List<AuthenticationToken> authenticationTokens) {
        return raMasterApi.getUserAccessSets(authenticationTokens);
    }

    @Override
    public List<CAInfo> getAuthorizedCas(final AuthenticationToken authenticationToken) {
        return raMasterApi.getAuthorizedCas(authenticationToken);
    }
    
    @Deprecated
    public String testCall(final AuthenticationToken authenticationToken, final String argument1, final int argument2) throws AuthorizationDeniedException, EjbcaException {
        return raMasterApi.testCall(authenticationToken, argument1, argument2);
    }

    @Override
    @Deprecated
    public String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    public List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    public String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException();
    }
}
