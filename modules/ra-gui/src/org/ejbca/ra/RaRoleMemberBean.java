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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.Role;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleMemberTokenTypeInfo;


/**
 * Backing bean for the (Add) Role Member page
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRoleMemberBean {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRoleMemberBean.class);
    
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAccessBean}")
    private RaAccessBean raAccessBean;
    public void setRaAccessBean(final RaAccessBean raAccessBean) { this.raAccessBean = raAccessBean; }
    
    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }
    
    private List<SelectItem> availableRoles = null;
    private List<SelectItem> availableTokenTypes = null;
    private List<SelectItem> availableCAs = null;
    private Map<String,RaRoleMemberTokenTypeInfo> tokenTypeInfos;
    
    private Integer roleMemberId;
    private RoleMember roleMember;
    
    private int roleId;
    private String tokenType;
    private int caId;
    private Integer matchType;
    private String matchValue;    
    
    public void initialize() throws AuthorizationDeniedException {
        tokenTypeInfos = raMasterApiProxyBean.getAuthorizedRoleMemberTokenTypes(raAuthenticationBean.getAuthenticationToken());
        
        if (roleMemberId != null) {
            roleMember = raMasterApiProxyBean.getRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMemberId);
            roleId = roleMember.getId();
            tokenType = roleMember.getTokenType();
            caId = roleMember.getTokenIssuerId();
            matchType = roleMember.getTokenMatchKey();
            matchValue = roleMember.getTokenMatchValue();
        } else {
            roleMember = new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, "", RoleMember.NO_ISSUER, 0, 0, "", 0, "", "");
            // Default values
            if (StringUtils.isEmpty(tokenType)) {
                tokenType = "CertificateAuthenticationToken";
            }
            
            if (matchType == null) {
                final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
                if (tokenTypeInfo != null) {
                    matchType = tokenTypeInfo.getMatchKeysMap().get(tokenTypeInfo.getDefaultMatchKey());
                } else {
                    log.debug("Missing information about token type " + tokenType);
                    matchType = 0;
                }
            }
        }
    }
    
    
    public Integer getRoleMemberId() {
        return roleMemberId;
    }

    public RoleMember getRoleMember() {
        return roleMember;
    }

    
    public Integer getRoleId() {
        return roleId;
    }
    
    public void setRoleId(final Integer roleId) {
        this.roleId = roleId;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(final String tokenType) {
        this.tokenType = tokenType;
    }

    public int getCaId() {
        return caId;
    }

    public void setCaId(final int caId) {
        this.caId = caId;
    }

    public int getMatchType() {
        return matchType;
    }

    public void setMatchType(final int matchType) {
        this.matchType = matchType;
    }

    public String getMatchValue() {
        return matchValue;
    }

    public void setMatchValue(final String matchValue) {
        this.matchValue = matchValue;
    }
    

    public List<SelectItem> getAvailableRoles() {
        if (availableRoles == null) {
            availableRoles = new ArrayList<>();
            final List<Role> roles = new ArrayList<>(raMasterApiProxyBean.getAuthorizedRoles(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(roles, new Comparator<Role>() {
                @Override
                public int compare(final Role role1, final Role role2) {
                    return role1.getRoleName().compareTo(role2.getRoleName());
                }
            });
            for (final Role role : roles) {
                availableRoles.add(new SelectItem(role.getRoleId(), role.getRoleName()));
            }
        }
        return availableRoles;
    }

    public List<SelectItem> getAvailableTokenTypes() {
        if (availableTokenTypes == null) {
            final List<String> tokenTypes = new ArrayList<>(tokenTypeInfos.keySet());
            Collections.sort(tokenTypes);
            availableTokenTypes = new ArrayList<>();
            for (final String tokenType : tokenTypes) {
                availableTokenTypes.add(new SelectItem(tokenType, raLocaleBean.getMessage("role_member_token_type_" + tokenType)));
            }
        }
        return availableTokenTypes;
    }

    public List<SelectItem> getAvailableCAs() {
        if (availableCAs == null) {
            availableCAs = new ArrayList<>();
            final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(caInfos, new Comparator<CAInfo>() {
                @Override
                public int compare(final CAInfo caInfo1, final CAInfo caInfo2) {
                    return caInfo1.getName().compareTo(caInfo2.getName());
                }
            });
            for (final CAInfo caInfo : caInfos) {
                availableCAs.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
            }
        }
        return availableCAs;
    }

    public List<SelectItem> getAvailableMatchTypes() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        final List<SelectItem> result = new ArrayList<>();
        if (tokenTypeInfo != null) {
            final List<String> namesSorted = new ArrayList<>(tokenTypeInfo.getMatchKeysMap().keySet());
            Collections.sort(namesSorted);
            for (final String name : namesSorted) {
                result.add(new SelectItem(tokenTypeInfo.getMatchKeysMap().get(name), name));
            }
        }
        return result;
    }


    public String save() throws AuthorizationDeniedException {
        // TODO validation etc.
        roleMember.setRoleId(roleId);
        roleMember.setTokenType(tokenType);
        roleMember.setTokenIssuerId(caId);
        roleMember.setTokenMatchKey(matchType);
        roleMember.setTokenMatchValue(matchValue);
        
        roleMember = raMasterApiProxyBean.saveRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMember);
        roleMemberId = roleMember.getId();
        
        // TODO if the active filter does not include the newly added role member, then change the filter to show it
        return "role_members?faces-redirect=true&includeViewParams=true";
    }    
    
}
