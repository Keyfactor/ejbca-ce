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
import java.math.BigInteger;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import jakarta.ejb.EJB;
import jakarta.faces.model.SelectItem;
import jakarta.faces.view.ViewScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;

import org.apache.commons.lang.SerializationUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.roles.Role;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleMemberTokenTypeInfo;

import com.keyfactor.util.StringTools;


/**
 * Backing bean for the (Add) Role Member page
 *
 */
@Named
@ViewScoped
public class RaRoleMemberBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRoleMemberBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @Inject
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    @Inject
    private RaRoleMembersBean raRoleMembersBean;
    public void setRaRoleMembersBean(final RaRoleMembersBean raRoleMembersBean) { this.raRoleMembersBean = raRoleMembersBean; }

    private List<SelectItem> availableRoles = null;
    private List<SelectItem> availableTokenTypes = null;
    private List<SelectItem> availableCAs = null;
    private List<SelectItem> availableOauthProviders = null;
    private Map<String,RaRoleMemberTokenTypeInfo> tokenTypeInfos;

    private Integer roleMemberId;
    private RoleMember roleMember;
    private Role role;

    private int roleId;
    private String tokenType;
    private int caId;
    private int providerId;
    private Integer matchKey;
    private String matchValue;
    private String description;

    public void initialize() {
        if (tokenType != null && tokenTypeInfos != null) {
            // Don't re-initialize, that would overwrite the fields (tokenType, etc.)
            return;
        }

        tokenTypeInfos = raMasterApiProxyBean.getAvailableRoleMemberTokenTypes(raAuthenticationBean.getAuthenticationToken());

        if (roleMemberId != null) {
            try {
                roleMember = raMasterApiProxyBean.getRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMemberId);
                if (roleMember == null) {
                    log.debug("Role member with ID " + roleMemberId + " was not found.");
                    return;
                }
                roleId = roleMember.getRoleId();
                tokenType = roleMember.getTokenType();
                caId = roleMember.getTokenIssuerId();
                providerId = roleMember.getTokenProviderId();
                matchKey = roleMember.getTokenMatchKey();
                matchValue = roleMember.getTokenMatchValue();
                description = roleMember.getDescription();
                if (roleId != RoleMember.NO_ROLE) {
                    role = raMasterApiProxyBean.getRole(raAuthenticationBean.getAuthenticationToken(), roleId);
                    if (role == null) {
                        log.debug("Reference to missing role with ID " + roleId + " in role member with ID " + roleMemberId);
                    }
                }
            } catch (AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization denied to role member " + roleMemberId + ". " + e.getMessage(), e);
                }
                roleMember = null;
            }
        } else {
            roleMember = new RoleMember("", RoleMember.NO_ISSUER, RoleMember.NO_PROVIDER, 0, 0, "", 0, "");
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

    public int getProviderId() {
        return providerId;
    }

    public void setProviderId(int providerId) {
        this.providerId = providerId;
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

    public String getDescription() {
        return this.description;
    }

    public void setDescription(final String description) {
        this.description = description.trim();
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
                    return caInfo1.getName().compareToIgnoreCase(caInfo2.getName());
                }
            });
            for (final CAInfo caInfo : caInfos) {
                availableCAs.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
            }
        }
        return availableCAs;
    }

    public List<SelectItem> getAvailableOauthProviders() {
        if (availableOauthProviders == null) {
            availableOauthProviders = new ArrayList<>();
            final OAuthConfiguration oAuthConfiguration = raMasterApiProxyBean.getGlobalConfiguration(OAuthConfiguration.class);
            if (oAuthConfiguration != null && oAuthConfiguration.getOauthKeys() != null) {
                final List<OAuthKeyInfo> oAuthKeyInfos = new ArrayList<>(oAuthConfiguration.getOauthKeys().values());
                Collections.sort(oAuthKeyInfos, new Comparator<OAuthKeyInfo>() {
                    @Override
                    public int compare(final OAuthKeyInfo oAuthKeyInfo1, final OAuthKeyInfo oAuthKeyInfo2) {
                        return oAuthKeyInfo1.getLabel().compareToIgnoreCase(oAuthKeyInfo2.getLabel());
                    }
                });
                for (final OAuthKeyInfo oAuthKeyInfo : oAuthKeyInfos) {
                    availableOauthProviders.add(new SelectItem(oAuthKeyInfo.getInternalId(), oAuthKeyInfo.getLabel()));
                }
            }
        }
        return availableOauthProviders;
    }

    public List<SelectItem> getAvailableMatchKeys() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        final List<SelectItem> result = new ArrayList<>();
        if (tokenTypeInfo != null) {
            final List<String> namesSorted = new ArrayList<>(tokenTypeInfo.getMatchKeysMap().keySet());
            Collator coll = Collator.getInstance();
            coll.setStrength(Collator.PRIMARY);
            Collections.sort(namesSorted, coll);
            for (final String name : namesSorted) {
                if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) && "NONE".equals(name) &&
                        !String.valueOf(matchKey).equals(tokenType)) {
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

    public boolean isTokenTypeIssuedByOauthProvider() {
        final RaRoleMemberTokenTypeInfo tokenTypeInfo = tokenTypeInfos.get(tokenType);
        return tokenTypeInfo == null || tokenTypeInfo.isIssuedByOauthProvider();
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
        if (!tokenTypeInfo.isIssuedByCA()) {
            caId = RoleMember.NO_ISSUER;
        }
        if (!tokenTypeInfo.isIssuedByOauthProvider()) {
            providerId = RoleMember.NO_PROVIDER;
        }
               
        if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) &&
                X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue() == matchKey) {
            matchValue = StringTools.removeAllWhitespaceAndColon(matchValue);
            try {
                new BigInteger(matchValue, 16);
            } catch (NumberFormatException e) {
                raLocaleBean.addMessageError("role_member_page_error_hexadecimal");
                return "";
            }
            
        } 
        
       

        // The getRoleMember method returns a reference to an object which should not be edited directly,
        // so we make a deep copy of it here, which we can edit freely. This code is not performance critical,
        // so cloning through serialization is OK (and does not require a copy constructor that needs to be maintained).
        final RoleMember roleMemberWithChanges = (RoleMember) SerializationUtils.clone(roleMember);
        roleMemberWithChanges.setRoleId(roleId);
        roleMemberWithChanges.setTokenType(tokenType);
        roleMemberWithChanges.setTokenIssuerId(caId);
        roleMemberWithChanges.setTokenProviderId(providerId);
        roleMemberWithChanges.setTokenMatchKey(matchKey);
        roleMemberWithChanges.setTokenMatchOperator(tokenTypeInfo.getMatchOperator());
        roleMemberWithChanges.setTokenMatchValue(getTokenTypeHasMatchValue() ? matchValue : "");
        roleMemberWithChanges.setDescription(description);

        final RoleMember savedRoleMember = raMasterApiProxyBean.saveRoleMember(raAuthenticationBean.getAuthenticationToken(), roleMemberWithChanges);
        if (savedRoleMember == null) {
            if (log.isDebugEnabled()) {
                log.debug("The role member could not be saved. Role member ID: " + roleMemberId + ". Role ID: " + roleId + ". Match value: '" + matchValue + "'");
            }
            raLocaleBean.addMessageError("role_member_page_error_generic");
            return "";
        }
        roleMember = savedRoleMember;
        roleMemberId = roleMember.getId();

        // If the active filter does not include the newly added role member, then change the filter to show it
        if (raRoleMembersBean.getCriteriaCaId() != null && raRoleMembersBean.getCriteriaCaId().intValue() != roleMember.getTokenIssuerId()) {
            raRoleMembersBean.setCriteriaCaId(caId != RoleMember.NO_ISSUER ? caId : null);
        }
        if (raRoleMembersBean.getCriteriaProviderId() != null && raRoleMembersBean.getCriteriaProviderId().intValue() != roleMember.getTokenProviderId()) {
            raRoleMembersBean.setCriteriaProviderId(providerId != RoleMember.NO_PROVIDER ? providerId : null);
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
        return raLocaleBean.getMessage("remove_role_member_page_title", StringUtils.defaultString(matchValue));
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
