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

package org.cesecore.authentication.tokens;

import java.security.Principal;
import java.util.HashSet;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.matchvalues.ApiKeyAccessMatchValue;

/**
 * TODO Not done at all
 * @version $Id$
 *
 */
public class ApiKeyAuthenticationToken extends AuthenticationToken {

    private static final ApiKeyAuthenticationTokenMetaData metaData = new ApiKeyAuthenticationTokenMetaData();
    
    private static final long serialVersionUID = 1L;
    
    private final String apiKey;
    private String apiKeyHash;

    public ApiKeyAuthenticationToken(String apiKey) {
        super(new HashSet<Principal>() {
            private static final long serialVersionUID = 1L;
            {
                add(new UsernamePrincipal("REST API"));
            }
        }, null);
        this.apiKey = apiKey;
    }

    @Override
    public boolean matches(AccessUserAspect accessUser) throws AuthenticationFailedException {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean equals(Object authenticationToken) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public int hashCode() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public AuthenticationTokenMetaData getMetaData() {
        return metaData;
    }

    @Override
    public int getPreferredMatchKey() {
        return ApiKeyAccessMatchValue.API_KEY.getNumericValue();
    }

    @Override
    public String getPreferredMatchValue() {
        return null;
    }

    @Override
    protected String generateUniqueId() {
        // TODO Auto-generated method stub
        return null;
    }

}