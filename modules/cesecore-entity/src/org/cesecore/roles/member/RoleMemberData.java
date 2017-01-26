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

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.builder.CompareToBuilder;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Entity bean for Role members. Does not correspond to a physical entity, but rather to an individual credential linked to an entity. The same 
 * individuals may share the same credential (such as belonging to the same organization, or sharing an account, while one individual may have access
 * to several credentials (such as a user using several different certificates for identification depending on location). 
 * 
 *  Each member is linked to a Role, though not intrinsically so via foreign keys 
 * 
 * @version $Id$
 */
@Entity
@Table(name = "RoleMemberData")
public class RoleMemberData extends ProtectedData implements Serializable, Comparable<RoleMemberData> {

    private static final long serialVersionUID = 1L;
   
    private int primaryKey;

    private String tokenType;
    private int tokenSubType;
    private int tokenIssuerId;
    private String tokenMatchValue;
    private int roleId;
    
    private String memberBindingType;
    private String memberBindingValue;
    
    private int rowVersion = 0;
    private String rowProtection;

    public RoleMemberData() {
        
    }
    
    /**
     * Constructor for a RoleMemberData object.
     * 
     * @param primaryKey the primary key for this object. It's required to check the database for any objects with the same key, otherwise that 
     *  object will be overridden
     * @param accessMatchValue the AccessMatchValue to match this object with, i.e CN, SN, etc.
     * @param tokenIssuerId the issuer of token if relevant or 0 otherwise
     * @param tokenMatchValue the actual value with which to match
     * @param roleId the ID of the role to which this member belongs. May be null.
     * @param memberBindingType the type of member binding used for this member. May be null.
     * @param memberBindingValue the member binding for this member. May be null.
     */
    public RoleMemberData(final int primaryKey, final AccessMatchValue accessMatchValue, final int tokenIssuerId, final String tokenMatchValue,
            final int roleId, String memberBindingType, String memberBindingValue) {
        this(primaryKey, accessMatchValue.getTokenType(), accessMatchValue.getNumericValue(), tokenIssuerId, tokenMatchValue, roleId, memberBindingType, memberBindingValue);
    }
    
    /**
     * Slightly more verbose constructor used for upgrades.
     * 
     * @param primaryKey the primary key for this object. It's required to check the database for any objects with the same key, otherwise that 
     *  object will be overridden
     * @param tokenType a string which defined the implementation of AcceessMatchValue used by this member
     * @param tokenSubType the integer value determining how to interpret the tokenMatchValue, defined in a class that inherits the interface AcceessMatchValue
     * @param tokenIssuerId the issuer of token if relevant or 0 otherwise
     * @param tokenMatchValue the actual value with which to match
     * @param roleId the ID of the role to which this member belongs. May be null.
     * @param memberBindingType the type of member binding used for this member. May be null.
     * @param memberBindingValue the member binding for this member. May be null.
     */
    public RoleMemberData(final int primaryKey, final String tokenType, final int tokenSubType, final int tokenIssuerId, final String tokenMatchValue,
            final int roleId, String memberBindingType, String memberBindingValue) {
        this.primaryKey = primaryKey;
        this.tokenType = tokenType;
        this.tokenSubType = tokenSubType;
        this.tokenIssuerId = tokenIssuerId;
        this.tokenMatchValue = tokenMatchValue;
        this.roleId = roleId;
        this.memberBindingType = memberBindingType;
        this.memberBindingValue = memberBindingValue;
    }

    /** @return the primary key of this entity bean, a pseudo-random integer */
    public int getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(int primaryKey) {
        this.primaryKey = primaryKey;
    }

    /** @return the authentication token type that this member identifies to (such as X509CertificateAuthenticationToken) */
    public String getTokenType() {
        return tokenType;
    }
    
    public void setTokenType(final String tokenType) {
        this.tokenType = tokenType;
    }

    /** @return the match value type with to match, i.e. CN, serial number, or username */
    public int getTokenSubType() {
        return tokenSubType;
    }

    public void setTokenSubType(int tokenSubType) {
        this.tokenSubType = tokenSubType;
    }
        
    /** @return issuer identifier of this token or 0 if this is not relevant for this token type */
    public int getTokenIssuerId() {
        return tokenSubType;
    }

    public void setTokenIssuerId(int tokenIssuerId) {
        this.tokenIssuerId = tokenIssuerId;
    }
        
    /** @return the actual value with which we match */
    public String getTokenMatchValue() {
        return tokenMatchValue;
    }
    
    public void setTokenMatchValue(final String tokenMatchValue) {
        this.tokenMatchValue = tokenMatchValue;
    }

    /** @return the role to which this member belongs or 0 if it is not assigned to a role. */
    public int getRoleId() {
        return roleId;
    }
    
    public void setRoleId(final int roleId) {
        this.roleId = roleId;
    }

    /** @return a string defining the class of member binding, which is a common value with which several members can be linked to one physical user. */
    public String getMemberBindingType() {
        return memberBindingType;
    }

    public void setMemberBindingType(String memberBindingType) {
        this.memberBindingType = memberBindingType;
    }

    /** @return a string referring to a member binding value, which can be used to string together several members to one physical user. */
    public String getMemberBindingValue() {
        return memberBindingValue;
    }

    public void setMemberBindingValue(String memberBindingValue) {
        this.memberBindingValue = memberBindingValue;
    }

    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    public String getRowProtection() {
        return rowProtection;
    }


    // Start Database integrity protection methods
    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // What is important to protect here is the data that we define
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getPrimaryKey()).append(getTokenType()).append(getTokenSubType()).append(getTokenIssuerId()).append(getTokenMatchValue()).append(
                getRoleId()).append(getMemberBindingType()).append(getMemberBindingValue());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return String.valueOf(getPrimaryKey());
    }

    //
    // End Database integrity protection methods
    //

    @Override
    public int compareTo(RoleMemberData o) {
        return new CompareToBuilder().append(this.tokenType, o.tokenType).append(this.tokenSubType, o.tokenSubType).append(this.tokenIssuerId, o.tokenIssuerId)
                .append(this.tokenMatchValue, o.tokenMatchValue).toComparison();
    }
    
    @Transient
    public RoleMember asValueObject() {
        return new RoleMember(primaryKey, AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(tokenType, tokenSubType),
                tokenIssuerId, tokenMatchValue, roleId, memberBindingType, memberBindingValue);
    }
}
