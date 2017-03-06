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
package org.cesecore.roles.member;

import java.io.Serializable;

import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.roles.Role;

/**
 * Value object for the RoleMemberData entity bean, so that we don't have to pass information like row protection remotely. 
 * 
 * @version $Id$
 */
public class RoleMember implements Serializable {
    
    public static int ROLE_MEMBER_ID_UNASSIGNED = 0;
    public static int NO_ROLE = Role.ROLE_ID_UNASSIGNED;
    public static int NO_ISSUER = 0;

    private static final long serialVersionUID = 1L;
    private int id;
    private String tokenType;
    private int tokenIssuerId;
    private int tokenMatchKey;
    private int tokenMatchOperator;
    private String tokenMatchValue;
    private int roleId;
    private String memberBindingType;
    private String memberBindingValue;
    
    /**
     * Constructor for a RoleMember object. Will by default be constructed with the primary key 0, which means that this object hasn't been
     * persisted yet. In that case, the primary key will be set by the CRUD bean. 
     * 
     * @param accessMatchValue the AccessMatchValue to match this object with, i.e CN, SN, etc. 
     * @param tokenIssuerId the issuer identifier of this token or 0 if not relevant
     * @param tokenMatchValue the actual value with which to match
     * @param roleId roleId the ID of the role to which this member belongs. May be null.
     * @param memberBindingType the type of member binding used for this member. May be null.
     * @param memberBinding the member binding for this member. May be null.
     */
    public RoleMember(final int id, final String tokenType, final int tokenIssuerId, final int tokenMatchKey, final int tokenMatchOperator,
            final String tokenMatchValue, final int roleId, final String memberBindingType, final String memberBindingValue) {
        this.id = id;
        this.tokenType = tokenType;
        this.tokenIssuerId = tokenIssuerId;
        this.tokenMatchKey = tokenMatchKey;
        this.tokenMatchOperator = tokenMatchOperator;
        this.tokenMatchValue = tokenMatchValue;
        this.roleId = roleId;
        this.memberBindingType = memberBindingType;
        this.memberBindingValue = memberBindingValue;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public int getTokenIssuerId() {
        return tokenIssuerId;
    }

    public void setTokenIssuerId(final int tokenIssuerId) {
        this.tokenIssuerId = tokenIssuerId;
    }

    public AccessMatchType getAccessMatchType() {
        return AccessMatchType.matchFromDatabase(tokenMatchOperator);
    }

    public int getTokenMatchKey() {
        return tokenMatchKey;
    }

    public void setTokenMatchKey(int tokenMatchKey) {
        this.tokenMatchKey = tokenMatchKey;
    }

    public int getTokenMatchOperator() {
        return tokenMatchOperator;
    }

    public void setTokenMatchOperator(int tokenMatchOperator) {
        this.tokenMatchOperator = tokenMatchOperator;
    }

    public String getTokenMatchValue() {
        return tokenMatchValue;
    }

    public void setTokenMatchValue(String tokenMatchValue) {
        this.tokenMatchValue = tokenMatchValue;
    }

    public int getRoleId() {
        return roleId;
    }

    public void setRoleId(int roleId) {
        this.roleId = roleId;
    }

    public String getMemberBindingType() {
        return memberBindingType;
    }

    public void setMemberBindingType(String memberBindingType) {
        this.memberBindingType = memberBindingType;
    }
    
    public String getMemberBindingValue() {
        return memberBindingValue;
    }

    public void setMemberBindingValue(String memberBindingValue) {
        this.memberBindingValue = memberBindingValue;
    }
}
