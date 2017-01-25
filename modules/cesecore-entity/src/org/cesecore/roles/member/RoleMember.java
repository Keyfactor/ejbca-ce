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

import org.cesecore.authorization.user.matchvalues.AccessMatchValue;

/**
 * Value object for the RoleMemberData entity bean, so that we don't have to pass information like row protection remotely. 
 * 
 * @version $Id$
 *
 */
public class RoleMember implements Serializable {

    private static final long serialVersionUID = 1L;
    private int id;
    private AccessMatchValue accessMatchValue;
    private String tokenMatchValue;
    private Integer roleId; 
    private String memberBindingType;
    private String memberBindingValue;
    
    /**
     * Constructor for a RoleMember object. Will by default be constructed with the primary key 0, which means that this object hasn't been
     * persisted yet. In that case, the primary key will be set by the CRUD bean. 
     * 
     * @param accessMatchValue the AccessMatchValue to match this object with, i.e CN, SN, etc. 
     * @param tokenMatchValue the actual value with which to match
     * @param roleId roleId the ID of the role to which this member belongs. May be null.
     * @param memberBindingType the type of member binding used for this member. May be null.
     * @param memberBinding the member binding for this member. May be null.
     */
    public RoleMember(int id, final AccessMatchValue accessMatchValue, final String tokenMatchValue, final int roleId, String memberBindingType, String memberBindingValue) {
        this.setId(id);
        this.setAccessMatchValue(accessMatchValue);
        this.setTokenMatchValue(tokenMatchValue);
        this.setRoleId(roleId);
        this.setMemberBindingType(memberBindingType);
        this.setMemberBindingValue(memberBindingValue);
     
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public AccessMatchValue getAccessMatchValue() {
        return accessMatchValue;
    }

    public void setAccessMatchValue(AccessMatchValue accessMatchValue) {
        this.accessMatchValue = accessMatchValue;
    }

    public String getTokenMatchValue() {
        return tokenMatchValue;
    }

    public void setTokenMatchValue(String tokenMatchValue) {
        this.tokenMatchValue = tokenMatchValue;
    }

    public Integer getRoleId() {
        return roleId;
    }

    public void setRoleId(Integer roleId) {
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
