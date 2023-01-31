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

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.roles.Role;
import org.cesecore.util.StringTools;

/**
 * Value object for the RoleMemberData entity bean, so that we don't have to pass information like row protection remotely.
 *
 */
public class RoleMember implements Serializable, Comparable<RoleMember> {

    public static int ROLE_MEMBER_ID_UNASSIGNED = 0;
    public static int NO_ROLE = Role.ROLE_ID_UNASSIGNED;
    public static int NO_ISSUER = 0;
    public static int NO_PROVIDER = 0;

    private static final long serialVersionUID = 1L;
    private int id;
    private String tokenType;
    private int tokenIssuerId;
    private int tokenProviderId;
    private int tokenMatchKey;
    private int tokenMatchOperator;
    private String tokenMatchValue;
    private int roleId;
    private String description;

    /**
     * Constructor for a new RoleMember. Will by default be constructed with the primary key 0, which means that this object hasn't been
     * persisted yet. In that case, the primary key will be set by the CRUD bean.
     *
     * @param tokenIssuerId the issuer identifier of this token or {@link #NO_ISSUER} if not relevant
     * @param tokenProviderId the OAuth provider identifier, or {@link #NO_PROVIDER} if not relevant
     * @param tokenMatchValue the actual value with which to match
     * @param roleId roleId the ID of the role to which this member belongs. May be null.
     * @param description a human readable description of this role member.
     */
    public RoleMember(final String tokenType, final int tokenIssuerId, final int tokenProviderId, final int tokenMatchKey, final int tokenMatchOperator,
            final String tokenMatchValue, final int roleId, final String description) {
        this(ROLE_MEMBER_ID_UNASSIGNED, tokenType, tokenIssuerId, tokenProviderId, tokenMatchKey, tokenMatchOperator, tokenMatchValue, roleId, description);
    }

    /**
     * Constructor for a RoleMember object that has already been assigned an ID (the RoleMember already exists).
     *
     * @param tokenIssuerId the issuer identifier of this token or {@link #NO_ISSUER} if not relevant
     * @param tokenProviderId the OAuth provider identifier, or {@link #NO_PROVIDER} if not relevant
     * @param tokenMatchValue the actual value with which to match
     * @param roleId roleId the ID of the role to which this member belongs. May be null.
     * @param description a human readable description of this role member.
     */
    public RoleMember(final int id, final String tokenType, final int tokenIssuerId, final int tokenProviderId, final int tokenMatchKey, final int tokenMatchOperator,
            final String tokenMatchValue, final int roleId, final String description) {
        this.id = id;
        this.tokenType = tokenType;
        this.tokenIssuerId = tokenIssuerId;
        this.tokenProviderId = tokenProviderId;
        this.tokenMatchKey = tokenMatchKey;
        this.tokenMatchOperator = tokenMatchOperator;
        this.tokenMatchValue = tokenMatchValue;
        this.roleId = roleId;
        this.description = description;
    }

    /** Copy constructor */
    public RoleMember(final RoleMember roleMember) {
        this.id = roleMember.id;
        this.tokenType = roleMember.tokenType;
        this.tokenIssuerId = roleMember.tokenIssuerId;
        this.tokenProviderId = roleMember.tokenProviderId;
        this.tokenMatchKey = roleMember.tokenMatchKey;
        this.tokenMatchOperator = roleMember.tokenMatchOperator;
        this.tokenMatchValue = roleMember.tokenMatchValue;
        this.roleId = roleMember.roleId;
        this.description = roleMember.description;
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

    public int getTokenProviderId() {
        return tokenProviderId;
    }

    public void setTokenProviderId(int tokenProviderId) {
        this.tokenProviderId = tokenProviderId;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isSameAs(final RoleMember roleMember) {
        return this.getTokenIssuerId() == roleMember.getTokenIssuerId() 
                && this.getTokenProviderId() == roleMember.getTokenProviderId()
                && this.getTokenMatchKey() == roleMember.getTokenMatchKey()
                && this.getTokenMatchOperator() == roleMember.getTokenMatchOperator()
                && StringUtils.equals(this.getTokenMatchValue(), roleMember.getTokenMatchValue())
                && StringUtils.equals(this.getTokenType(), roleMember.getTokenType());
    }

    @Override
    public int compareTo(final RoleMember o) {
        if (roleId != o.roleId) {
            return roleId - o.roleId;
        }
        int diff;
        diff = StringTools.compare(tokenType, o.tokenType);
        if (diff != 0) {
            return diff;
        }
        if (tokenIssuerId != o.tokenIssuerId) {
            return tokenIssuerId - o.tokenIssuerId;
        }
        if (tokenProviderId!= o.tokenProviderId) {
            return tokenProviderId - o.tokenProviderId;
        }
        diff = StringTools.compare(tokenMatchKey, o.tokenMatchKey);
        if (diff != 0) {
            return diff;
        }
        diff = StringTools.compare(tokenMatchOperator, o.tokenMatchOperator);
        if (diff != 0) {
            return diff;
        }
        diff = StringTools.compare(tokenMatchValue, o.tokenMatchValue);
        if (diff != 0) {
            return diff;
        }
        diff = StringTools.compare(description, o.description);
        if (diff != 0) {
            return diff;
        }
        return 0;
    }
}
