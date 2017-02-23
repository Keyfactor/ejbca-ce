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

import java.util.regex.Pattern;

import org.cesecore.roles.member.RoleMember;

/**
 * @version $Id$
 */
public final class RaRoleMemberGUIInfo {
    
    private static final Pattern serialNumberPattern = Pattern.compile("^[0-9A-Fa-f]{8,}$");
    
    public final RoleMember roleMember;
    public final String caName;
    public final String roleName;
    public final String tokenTypeText;
    
    public RaRoleMemberGUIInfo(final RoleMember roleMember, final String caName, final String roleName, final String tokenTypeText) {
        this.roleMember = roleMember;
        this.caName = caName;
        this.roleName = roleName;
        this.tokenTypeText = tokenTypeText;
    }

    public RoleMember getRoleMember() {
        return roleMember;
    }

    public String getCaName() {
        return caName;
    }
    
    public String getRoleName() {
        return roleName;
    }
    
    public String getTokenTypeText() {
        return tokenTypeText;
    }
    
    public boolean getTokenMatchValueIsLink() {
        return roleMember.getTokenMatchValue() != null && serialNumberPattern.matcher(roleMember.getTokenMatchValue()).matches();
    }
    
}
