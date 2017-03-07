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

import java.io.Serializable;
import java.text.Collator;
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
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
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
public class RaRoleMemberBean implements Serializable {

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
    
    @ManagedProperty(value="#{raRoleMembersBean}")
    private RaRoleMembersBean raRoleMembersBean;
    public void setRaRoleMembersBean(final RaRoleMembersBean raRoleMembersBean) { this.raRoleMembersBean = raRoleMembersBean; }
    
    private List<SelectItem> availableRoles = null;
    private List<SelectItem> availableTokenTypes = null;
    private List<SelectItem> availableCAs = null;
    private Map<String,RaRoleMemberTokenTypeInfo> tokenTypeInfos;
    
    private Integer roleMemberId;
    private RoleMember roleMember;
    private Role role;
    
    private int roleId;
    private String tokenType;
    private int caId;
    private Integer matchKey;
    private String matchValue;
    
    public void initialize() throws AuthorizationDeniedException {
        if (tokenType != null && tokenTypeInfos != null) {
            // Don't re-initialize, that would overwrite the fields (tokenType, etc.)
            return;
        }
        
        tokenTypeInfos = raMasterApiProxyBean.getAvailableRoleMemberTokenTypes(raAuthenticationBean.getAuthenticationToken());
        
        if (roleMemberId != null) {
            roleMember = raMasterApiProxyBean.getRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMemberId);
            roleId = roleMember.getRoleId();
            tokenType = roleMember.getTokenType();
            caId = roleMember.getTokenIssuerId();
            matchKey = roleMember.getTokenMatchKey();
            matchValue = roleMember.getTokenMatchValue();
            if (roleId != RoleMember.NO_ROLE) {
                role = raMasterApiProxyBean.getRole(raAuthenticationBean.getAuthenticationToken(), roleId);
                if (role == null) {
                    log.debug("Reference to missing role with ID " + roleId + " in role member with ID " + roleMemberId);
                }
            }
        } else {
            roleMember = new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, "", RoleMember.NO_ISSUER, 0, 0, "", 0, "", "");
            // Default values
            if (StringUtils.isEmpty(tokenType)) {
                tokenType = "CertificateAuthenticationToken";
            }
            
            if (matchKey == null) {
                final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
                if (tokenTypeInfo != null) {
                    matchKey = tokenTypeInfo.getMatchKeysMap().get(tokenTypeInfo.getDefaultMatchKey());
                } else {
                    log.debug("Missing information about token type " + tokenType);
                    matchKey = 0;
                }
            }
        }
    }
    
    
    public Integer getRoleMemberId() {
        return roleMemberId;
    }
    
    public void setRoleMemberId(final Integer roleMemberId) {
        this.roleMemberId = roleMemberId;
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

    public int getMatchKey() {
        return matchKey;
    }

    public void setMatchKey(final int matchKey) {
        this.matchKey = matchKey;
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
            Collections.sort(roles);
            boolean hasNamespaces = false;
            for (final Role role : roles) {
                if (!StringUtils.isEmpty(role.getNameSpace())) {
                    hasNamespaces = true;
                }
            }
            for (final Role role : roles) {
                final String name = hasNamespaces ? role.getRoleNameFull() : role.getRoleName();
                availableRoles.add(new SelectItem(role.getRoleId(), name));
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

    public List<SelectItem> getAvailableMatchKeys() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        final List<SelectItem> result = new ArrayList<>();
        if (tokenTypeInfo != null) {
            final List<String> namesSorted = new ArrayList<>(tokenTypeInfo.getMatchKeysMap().keySet());
            Collator coll = Collator.getInstance();
            coll.setStrength(Collator.PRIMARY);
            Collections.sort(namesSorted);
            for (final String name : namesSorted) {
                if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) && "NONE".equals(name) &&
                        !matchKey.equals(tokenType)) {
                    continue; // deprecated value
                }
                result.add(new SelectItem(tokenTypeInfo.getMatchKeysMap().get(name), raLocaleBean.getMessage("role_member_matchkey_" + tokenType + "_" + name)));
            }
        }
        return result;
    }
    
    public boolean isTokenTypeIssuedByCA() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        return tokenTypeInfo == null || tokenTypeInfo.isIssuedByCA();
    }
    
    public boolean getTokenTypeHasMatchValue() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        return tokenTypeInfo.getHasMatchValue();
    }

    public String getEditPageTitle() {
        return raLocaleBean.getMessage(roleMemberId != null ? "role_member_page_edit_title" : "role_member_page_add_title");
    }
    
    public String getSaveButtonText() {
        return raLocaleBean.getMessage(roleMemberId != null ? "role_member_page_save_command" : "role_member_page_add_command");
    }
    
    /** Called when the token type is changed. Does nothing */
    public void update() {
    }
    
    public String save() throws AuthorizationDeniedException {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        if (tokenTypeInfo.isIssuedByCA()) {
            caId = RoleMember.NO_ISSUER;
        }
        
        roleMember.setRoleId(roleId);
        roleMember.setTokenType(tokenType);
        roleMember.setTokenIssuerId(caId);
        roleMember.setTokenMatchKey(matchKey);
        roleMember.setTokenMatchOperator(tokenTypeInfo.getMatchOperator());
        roleMember.setTokenMatchValue(getTokenTypeHasMatchValue() ? matchValue : "");
        
        roleMember = raMasterApiProxyBean.saveRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMember);
        if (roleMember == null) {
            if (log.isDebugEnabled()) {
                log.debug("The role member could not be saved. Role member ID: " + roleMemberId + ". Role ID: " + roleId + ". Match value: '" + matchValue + "'");
            }
            raLocaleBean.addMessageError("role_member_page_error_generic");
            return "";
        }
        roleMemberId = roleMember.getId();
        
        // If the active filter does not include the newly added role member, then change the filter to show it
        if (raRoleMembersBean.getCriteriaCaId() != null && raRoleMembersBean.getCriteriaCaId().intValue() != roleMember.getTokenIssuerId()) {
            raRoleMembersBean.setCriteriaCaId(caId != RoleMember.NO_ISSUER ? caId : null);
        }
        
        if (raRoleMembersBean.getCriteriaTokenType() != null && !raRoleMembersBean.getCriteriaTokenType().equals(roleMember.getTokenType())) {
            raRoleMembersBean.setCriteriaTokenType(tokenType);
        }
        
        if (raRoleMembersBean.getCriteriaRoleId() != null && raRoleMembersBean.getCriteriaRoleId().intValue() != roleMember.getRoleId()) {
            raRoleMembersBean.setCriteriaRoleId(roleId);
        }
        
        return "role_members?faces-redirect=true&includeViewParams=true";
    }
    

    public String getRemovePageTitle() {
        return raLocaleBean.getMessage("remove_role_member_page_title", matchValue);
    }
    
    public String getRemoveConfirmationText() {
        if (role != null) {
            return raLocaleBean.getMessage("remove_role_member_page_confirm_with_role", role.getRoleName());
        } else {
            return raLocaleBean.getMessage("remove_role_member_page_confirm");
        }
    }
    
    public String delete() throws AuthorizationDeniedException {
        if (!raMasterApiProxyBean.deleteRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMember.getRoleId(), roleMember.getId())) {
            if (log.isDebugEnabled()) {
                log.debug("The role member could not be deleted. Role member ID: " + roleMemberId + ". Role ID: " + roleId + ". Match value: '" + matchValue + "'");
            }
            raLocaleBean.addMessageError("remove_role_member_page_error_generic");
            return "";
        }
        return "role_members?faces-redirect=true&includeViewParams=true";
    }
    
    public String cancel() {
        return "role_members?faces-redirect=true&includeViewParams=true";
    }
    
}
