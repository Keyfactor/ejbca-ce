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

package org.cesecore.authorization.user;

import java.io.Serializable;

import org.cesecore.roles.member.RoleMember;

/**
 * Class describing the matching aspect for a role
 *
 */
public class AccessUserAspectImpl implements Serializable, AccessUserAspect {

    private static final long serialVersionUID = 1L;

    private final RoleMember roleMember;
    
    public AccessUserAspectImpl(final RoleMember roleMember) {
        this.roleMember = roleMember;
    }
    
    @Override
    public int getMatchWith() {
        return roleMember.getTokenMatchKey();
    }

    
    @Override
    public int getMatchType() {
        return roleMember.getTokenMatchOperator();
    }

    
    @Override
    public AccessMatchType getMatchTypeAsType() {
        return AccessMatchType.matchFromDatabase(roleMember.getTokenMatchOperator());
    }
    
    @Override
    public String getMatchValue() {
        return roleMember.getTokenMatchValue();
    }

    
    @Override
    public Integer getCaId() {
        return roleMember.getTokenIssuerId();
    }
    
    @Override
    public Integer getOauthProviderId() {
        return roleMember.getTokenProviderId();
    }

    
    @Override
    public String getTokenType() {
        return (roleMember == null ? null : roleMember.getTokenType());
    }
   
}