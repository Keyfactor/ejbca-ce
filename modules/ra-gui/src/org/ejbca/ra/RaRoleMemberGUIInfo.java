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

import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.roles.member.RoleMember;

/**
 * @version $Id$
 */
public final class RaRoleMemberGUIInfo {
    
    public final RoleMember roleMember;
    public final String caName;
    public final String roleName;
    public final String roleNamespace;
    public final String tokenTypeText;
    public final boolean tokenMatchValueIsLink;
    
    public RaRoleMemberGUIInfo(final RoleMember roleMember, final String caName, final String roleName, final String roleNamespace, final String tokenTypeText) {
        this.roleMember = roleMember;
        this.caName = caName;
        this.roleName = roleName;
        this.roleNamespace = roleNamespace;
        this.tokenTypeText = tokenTypeText;
        this.tokenMatchValueIsLink = X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(roleMember.getTokenType()) &&
                roleMember.getTokenMatchKey() == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue();
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
    
    public String getRoleNamespace() {
        return roleNamespace;
    }
    
    public String getTokenTypeText() {
        return tokenTypeText;
    }
    
    public boolean getTokenMatchValueIsLink() {
        return tokenMatchValueIsLink;
    }
    
}
