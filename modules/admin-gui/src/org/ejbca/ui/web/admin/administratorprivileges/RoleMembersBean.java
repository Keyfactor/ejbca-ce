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
package org.ejbca.ui.web.admin.administratorprivileges;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Managed Bean for the Role Member manage/view page.
 * 
 * @version $Id$
 */
@ViewScoped
@ManagedBean
public class RoleMembersBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RoleMembersBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;

    private String roleIdParam;
    private Role role;

    private List<SelectItem> matchWithItems = null;
    private String matchWithSelected = X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE + ":" + X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue();
    private Integer tokenIssuerId;
    private String tokenMatchValue = "";

    private ListDataModel<RoleMember> roleMembers = null;
    private RoleMember roleMemberToDelete = null;

    @PostConstruct
    private void postConstruct() {
        // Read HTTP param "roleId" that should be interpreted as an integer
        roleIdParam = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("roleId");
    }
    
    /** Redirect back to this page with the correct roleId for non-ajax requests */
    private void nonAjaxPostRedirectGet() {
        super.nonAjaxPostRedirectGet("?roleId="+roleIdParam);
    }

    /** @return true when admin is authorized to edit members of this role */
    public boolean isAuthorizedToEditRole() {
        try {
            if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EDITROLES.resource()) && getRole()!=null) {
                roleSession.assertAuthorizedToRoleMembers(getAdmin(), getRole().getRoleId(), true);
                return true;
            }
        } catch (AuthorizationDeniedException e) {
            // NOPMD: Ignore.. would be nicer with a API call returning a boolean
        }
        return false;
    }

    /** @return an authorized existing role based on the roleId HTTP param or null if no such role was found. */
    public Role getRole() {
        if (role==null && StringUtils.isNumeric(roleIdParam)) {
            try {
                role = roleSession.getRole(getAdmin(), Integer.parseInt(roleIdParam));
                if (role==null && log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access non-existing role.");
                }
            } catch (NumberFormatException | AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Admin '" + getAdmin() + "' failed to access a role: " + e.getMessage());
                }
            }
        }
        return role;
    }

    /** @return a ListDataModel of all RoleMembers in this Role (sorted) */
    public ListDataModel<RoleMember> getRoleMembers() {
        if (roleMembers==null) {
            final List<RoleMember> roleMembers = roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId());
            Collections.sort(roleMembers, new Comparator<RoleMember>() {
                @Override
                public int compare(final RoleMember roleMember1, final RoleMember roleMember2) {
                    final String matchWithItemString1 = getMatchWithItemString(roleMember1);
                    final String matchWithItemString2 = getMatchWithItemString(roleMember2);
                    final int compareA = matchWithItemString1.compareTo(matchWithItemString2);
                    if (compareA!=0) {
                        return compareA;
                    }
                    final String tokenIssuerIdString1 = getTokenIssuerIdString(roleMember1);
                    final String tokenIssuerIdString2 = getTokenIssuerIdString(roleMember2);
                    final int compareB = tokenIssuerIdString1.compareTo(tokenIssuerIdString2);
                    if (compareB!=0) {
                        return compareB;
                    }
                    return roleMember1.getTokenMatchValue().compareTo(roleMember2.getTokenMatchValue());
                }
            });
            this.roleMembers = new ListDataModel<>(roleMembers);
        }
        return roleMembers;
    }

    /** @return a viewable list of 'match with'-texts */
    public List<SelectItem> getMatchWithItems() {
        if (matchWithItems == null) {
            matchWithItems = new ArrayList<>();
            final List<String> tokenTypes = new ArrayList<String>(AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes());
            Collections.sort(tokenTypes);
            for (final String tokenType : tokenTypes) {
                final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
                if (authenticationTokenMetaData.isUserConfigurable()) {
                    for (final AccessMatchValue accessMatchValue : authenticationTokenMetaData.getAccessMatchValues()) {
                        // Special exclusion of this rather useless match value that will never match anything
                        if (!X500PrincipalAccessMatchValue.NONE.equals(accessMatchValue)) {
                            matchWithItems.add(new SelectItem(tokenType + ":" + accessMatchValue.getNumericValue(), 
                                    getEjbcaWebBean().getText(tokenType) + ": " + getEjbcaWebBean().getText(accessMatchValue.name())));
                        }
                    }
                }
            }
        }
        return matchWithItems;
    }

    /** @return the selected tokenType and tokenMatchKey combo */
    public String getMatchWithSelected() { return matchWithSelected; }
    /** Set the selected tokenType and tokenMatchKey combo */
    public void setMatchWithSelected(final String matchWithSelected) { this.matchWithSelected = matchWithSelected; }

    /** @return a human readable version of the tokenType and tokenMatchKey values */
    public String getMatchWithItemString(final RoleMember roleMember) {
        final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(roleMember.getTokenType());
        final String tokenTypeString = getEjbcaWebBean().getText(authenticationTokenMetaData.getTokenType());
        final String tokenMatchKeyString = getEjbcaWebBean().getText(authenticationTokenMetaData.getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey()).name());
        return tokenTypeString + ":" + tokenMatchKeyString;
    }

    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that is has been issued by a CA */
    public boolean isRenderTokenIssuerIdInput() {
        return getAccessMatchValue(getSelectedTokenType(), getSelectedTokenMatchKey()).isIssuedByCa();
    }

    /** @return a List of (SelectItem<Integer, String>) authorized CAs */
    public List<SelectItem> getAvailableCas() {
        final List<SelectItem> availableCas = new ArrayList<>();
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        final List<Integer> authorizedCaIds = caSession.getAuthorizedCaIds(getAdmin());
        for (final int caId : authorizedCaIds) {
            availableCas.add(new SelectItem(caId, caIdToNameMap.get(caId)));
        }
        super.sortSelectItemsByLabel(availableCas);
        return availableCas;
    }

    /** @return the currently selected CA if any */
    public Integer getTokenIssuerId() { return tokenIssuerId; }
    /** Set the currently selected CA */
    public void setTokenIssuerId(final Integer tokenIssuerId) { this.tokenIssuerId = tokenIssuerId; }

    /** @return a human readable version of the RoleMember's tokenIsserId (CA name) */
    public String getTokenIssuerIdString(final RoleMember roleMember) {
        final int tokenIssuerId = roleMember.getTokenIssuerId();
        if (tokenIssuerId==RoleMember.NO_ISSUER) {
            return "-";
        }
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        return caIdToNameMap.get(tokenIssuerId);
    }

    /** @return a human readable version of the RoleMember's tokenMatchOperator */
    public String getTokenMatchOperatorString(final RoleMember roleMember) {
        return getEjbcaWebBean().getText(AccessMatchType.matchFromDatabase(roleMember.getTokenMatchOperator()).name());
    }

    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that it needs a tokenMatchValue */
    public boolean isRenderTokenMatchValueInput() {
        return !getAccessMatchValue(getSelectedTokenType(), getSelectedTokenMatchKey()).getAvailableAccessMatchTypes().isEmpty();
    }

    /** @return the current tokenMatchValue */
    public String getTokenMatchValue() { return tokenMatchValue; }
    /** Set the current tokenMatchValue */
    public void setTokenMatchValue(final String tokenMatchValue) { this.tokenMatchValue = tokenMatchValue.trim(); }
    
    /** @return true if the currently selected tokenType and tokenMatchKey combo implies that the tokenMatchValue is a hex certificate serial number */
    public boolean isRenderCertificateLink(final RoleMember roleMember) {
        return X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(roleMember.getTokenType()) &&
                X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue() == roleMember.getTokenMatchKey();
    }

    /** @return the tokenType from the currently selected tokenType and tokenMatchKey combo */
    private String getSelectedTokenType() {
        return matchWithSelected.split(":")[0];
    }
    /** @return the tokenMatchKey from the currently selected tokenType and tokenMatchKey combo */
    private int getSelectedTokenMatchKey() {
        return Integer.parseInt(matchWithSelected.split(":")[1]);
    }
    /** @return the AccessMatchValue from the specified tokenType and tokenMatchKey combo */
    private AccessMatchValue getAccessMatchValue(final String tokenType, final int tokenMatchKey) {
        final AuthenticationTokenMetaData metaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
        return metaData.getAccessMatchValueIdMap().get(tokenMatchKey);
    }

    /** Invoked by the admin when adding a new RoleMember. */
    public void actionAddRoleMember() {
        try {
            final String tokenType = getSelectedTokenType();
            final int tokenMatchKey = getSelectedTokenMatchKey();
            final AccessMatchValue accessMatchValue = getAccessMatchValue(tokenType, tokenMatchKey);
            final AccessMatchType accessMatchType;
            if (accessMatchValue.getAvailableAccessMatchTypes().isEmpty()) {
                accessMatchType = AccessMatchType.TYPE_UNUSED;
            } else {
                // Just grab the first one, since we according to ECA-3164 only will have a single allowed match operator for each match key
                accessMatchType = accessMatchValue.getAvailableAccessMatchTypes().get(0);
            }
            if (AccessMatchType.TYPE_UNUSED.equals(accessMatchType)) {
                tokenMatchValue = "";
            } else {
                // Validate that a required tokenMatchValue has been entered
                if (StringUtils.isEmpty(tokenMatchValue)) {
                    super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "MATCHVALUEREQUIRED");
                    return;
                }
            }
            // Validate that the tokenMatchValue contains no illegal characters
            // (Check this here instead of using an f:validator validatorId="legalCharsValidator" since we might need to do PRG later)
            if (StringTools.hasSqlStripChars(tokenMatchValue)) {
                super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "INVALIDCHARS");
                return;
            }
            // If the tokenMatchValue should be a hex number, validate that it is
            if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType) &&
                    X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue()==tokenMatchKey) {
                try {
                    new BigInteger(tokenMatchValue, 16);
                } catch (NumberFormatException e) {
                    super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "HEXREQUIRED");
                    return;
                }
            }
            final int tokenIssuerId;
            if (accessMatchValue.isIssuedByCa()) {
                tokenIssuerId = this.tokenIssuerId;
            } else {
                tokenIssuerId = RoleMember.NO_ISSUER;
            }
            // Placeholders for meta data about each role member
            final String memberBindingType = null;
            final String memberBindingValue = null;
            try {
                roleMemberSession.createOrEdit(getAdmin(), new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, tokenType, tokenIssuerId, tokenMatchKey,
                        accessMatchType.getNumericValue(), tokenMatchValue, role.getRoleId(), memberBindingType, memberBindingValue));
            } catch (AuthorizationDeniedException e) {
                super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "AUTHORIZATIONDENIED");
            }
            // Only reset this one, since admin might want to add additional matches of the same type
            tokenMatchValue = "";
            // Trigger a reload of the RoleMember list (if this is an AJAX requests and no new viewscope will be created)
            roleMembers = null;
        } finally {
            nonAjaxPostRedirectGet();
        }
    }

    /** @return true if the RoleMember's tokenType and tokenMatchKey combo implies that it is issued by a CA */
    public boolean isTokenIssuerIdUsed(final RoleMember roleMember) {
        return getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey()).isIssuedByCa();
    }

    /** @return true if the RoleMember's tokenType and tokenMatchKey combo implies a tokenMatchValue is used */
    public boolean isTokenMatchValueUsed(final RoleMember roleMember) {
        return !getAccessMatchValue(roleMember.getTokenType(), roleMember.getTokenMatchKey()).getAvailableAccessMatchTypes().isEmpty();
    }

    /** @return the RoleMember that has been selected for deletion */
    public RoleMember getRoleMemberToDelete() {
        return roleMemberToDelete;
    }
    /** @return true if a RoleMember that has been selected for deletion */
    public boolean isRenderDeleteRoleMember() {
        return roleMemberToDelete!=null;
    }
    /** Invoked by the admin to start the process of deleting a RoleMember */
    public void actionDeleteRoleMemberStart() {
        roleMemberToDelete = getRoleMembers().getRowData();
    }
    /** Invoked by the admin to cancel the process of deleting a RoleMember */
    public void actionDeleteRoleMemberReset() {
        roleMemberToDelete = null;
        nonAjaxPostRedirectGet();
    }
    /** Invoked by the admin to confirm the process of deleting a RoleMember */
    public void actionDeleteRoleMemberConfirm() {
        try {
            roleMemberSession.remove(getAdmin(), roleMemberToDelete.getId());
            super.addGlobalMessage(FacesMessage.SEVERITY_INFO, "ROLEMEMBERS_INFO_REMOVED");
            roleMembers = null;
            roleMemberToDelete = null;
            nonAjaxPostRedirectGet();
        } catch (AuthorizationDeniedException e) {
            super.addGlobalMessage(FacesMessage.SEVERITY_ERROR, "ROLEMEMBERS_ERROR_UNAUTH", e.getMessage());
        }
    }
}
