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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for role members from RA UI.
 * 
 * @version $Id$
 */
public class RaRoleMemberSearchRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<Integer> roleIds = new ArrayList<>();
    private List<Integer> caIds = new ArrayList<>();
    private List<String> tokenTypes = new ArrayList<>();
    private String genericSearchString = "";
    //private boolean genericSearchExact = false;

    /** Default constructor */
    public RaRoleMemberSearchRequest() {}
    
    /** Copy constructor */
    public RaRoleMemberSearchRequest(final RaRoleMemberSearchRequest request) {
        roleIds.addAll(request.roleIds);
        caIds.addAll(request.caIds);
        genericSearchString = request.genericSearchString;
        //genericSearchExact = request.genericSearchExact;
    }

    public List<Integer> getRoleIds() { return roleIds; }
    public void setRoleIds(final List<Integer> roleIds) { this.roleIds = roleIds; }
    public List<Integer> getCaIds() { return caIds; }
    public void setCaIds(final List<Integer> caIds) { this.caIds = caIds; }
    public List<String> getTokenTypes() { return tokenTypes; }
    public void setTokenType(final List<String> tokenTypes) { this.tokenTypes = tokenTypes; }
    public String getGenericSearchString() { return genericSearchString; }
    /** Prefix string to search for in the subject DN, or full serial number. */
    public void setGenericSearchString(final String genericSearchString) { this.genericSearchString = genericSearchString; }
//    public boolean isGenericSearchString() { return genericSearchExact; }
//    public void setGenericSearchString(final boolean genericSearchExact) { this.genericSearchExact = genericSearchExact; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

}
