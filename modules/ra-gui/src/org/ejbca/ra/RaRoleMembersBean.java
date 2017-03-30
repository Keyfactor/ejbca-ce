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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.roles.Role;
import org.cesecore.roles.member.RoleMember;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaRoleMemberSearchRequest;
import org.ejbca.core.model.era.RaRoleMemberSearchResponse;
import org.ejbca.core.model.era.RaRoleMemberTokenTypeInfo;


/**
 * Backing bean for the Role Members page
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRoleMembersBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRoleMembersBean.class);
    
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
    private List<SelectItem> availableCas = null;
    private List<SelectItem> availableTokenTypes = null;
    private Map<String,RaRoleMemberTokenTypeInfo> tokenTypeInfos;
    
    private String genericSearchString;
    private Integer criteriaRoleId;
    private Integer criteriaCaId;
    private String criteriaTokenType;
    private boolean fromRolesPage;
    
    private RaRoleMemberSearchResponse lastExecutedResponse = null;
    
    private List<RaRoleMemberGUIInfo> resultsFiltered = new ArrayList<>();
    private Map<Integer,String> caIdToNameMap;
    private Map<Integer,String> roleIdToNameMap;
    private Map<Integer,String> roleIdToNamespaceMap;
    private boolean hasMultipleNamespaces;
    
    private enum SortBy { ROLE, ROLENAMESPACE, CA, TOKENTYPE, TOKENMATCHVALUE, DESCRIPTION };
    private SortBy sortBy = SortBy.ROLE;
    private boolean sortAscending = true;
    
    
    public void initialize() {
        searchAndFilterCommon();
    }
    
    public String getGenericSearchString() {
        return genericSearchString;
    }
    
    public void setGenericSearchString(final String genericSearchString) {
        this.genericSearchString = genericSearchString;
    }

    public Integer getCriteriaRoleId() {
        return criteriaRoleId;
    }

    public void setCriteriaRoleId(final Integer criteriaRoleId) {
        this.criteriaRoleId = criteriaRoleId;
    }

    public Integer getCriteriaCaId() {
        return criteriaCaId;
    }

    public void setCriteriaCaId(final Integer criteriaCaId) {
        this.criteriaCaId = criteriaCaId;
    }
    
    public String getCriteriaTokenType() {
        return criteriaTokenType;
    }

    public void setCriteriaTokenType(final String criteriaTokenType) {
        this.criteriaTokenType = criteriaTokenType;
    }
    
    public boolean isFromRolesPage() {
        return fromRolesPage;
    }
    
    public void setFromRolesPage(final boolean fromRolesPage) {
        this.fromRolesPage = fromRolesPage;
    }


    /** Invoked action on search form post */
    public void searchAndFilterAction() {
        searchAndFilterCommon();
    }

    /** Invoked on criteria changes */
    public void searchAndFilterAjaxListener(final AjaxBehaviorEvent event) {
        searchAndFilterCommon();
    }
    
    /** Determine if we need to query back end or just filter and execute the required action. */
    private void searchAndFilterCommon() {
        // First make sure we have all CA and Role names
        getAvailableCas();
        getAvailableRoles();
        
        // Make search request
        final RaRoleMemberSearchRequest searchRequest = new RaRoleMemberSearchRequest();
        if (criteriaCaId != null && criteriaCaId.intValue() != 0) { // JBoss EAP 6.4 sets the parameters to 0 instead of null
            searchRequest.setCaIds(new ArrayList<>(Arrays.asList(criteriaCaId)));
        }
        if (criteriaRoleId != null && criteriaRoleId.intValue() != 0) {
            searchRequest.setRoleIds(new ArrayList<>(Arrays.asList(criteriaRoleId)));
        }
        if (!StringUtils.isEmpty(criteriaTokenType)) {
            searchRequest.setTokenTypes(new ArrayList<>(Arrays.asList(criteriaTokenType)));
        }
        searchRequest.setGenericSearchString(genericSearchString);
        lastExecutedResponse = raMasterApiProxyBean.searchForRoleMembers(raAuthenticationBean.getAuthenticationToken(), searchRequest);
        
        // Add names of CAs and roles
        resultsFiltered = new ArrayList<>();
        for (final RoleMember member : lastExecutedResponse.getRoleMembers()) {
            final String caName = StringUtils.defaultString(caIdToNameMap.get(member.getTokenIssuerId()), raLocaleBean.getMessage("role_members_page_info_unknownca"));
            final String roleName = StringUtils.defaultString(roleIdToNameMap.get(member.getRoleId()));
            final String namespace = roleIdToNamespaceMap.get(member.getRoleId());
            final String tokenTypeText = raLocaleBean.getMessage("role_member_token_type_" + member.getTokenType());
            resultsFiltered.add(new RaRoleMemberGUIInfo(member, caName, roleName, StringUtils.defaultString(namespace), tokenTypeText));
        }
        
        sort();
    }
    
    public List<RaRoleMemberGUIInfo> getFilteredResults() {
        return resultsFiltered;
    }
    
    public boolean isMoreResultsAvailable() {
        return lastExecutedResponse.isMightHaveMoreResults();
    }
    
    // Sorting
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<RaRoleMemberGUIInfo>() {
            @Override
            public int compare(RaRoleMemberGUIInfo o1, RaRoleMemberGUIInfo o2) {
                int sortDir = (isSortAscending() ? 1 : -1);
                final RoleMember rm1 = o1.getRoleMember();
                final RoleMember rm2 = o2.getRoleMember();
                switch (sortBy) {
                // TODO locale-aware sorting
                case ROLE: {
                    int diff = o1.getRoleName().compareTo(o2.getRoleName()) * sortDir;
                    if (diff != 0) {
                        return diff;
                    } else {
                        return o1.getRoleNamespace().compareTo(o2.getRoleNamespace()) * sortDir;
                    }
                }
                case ROLENAMESPACE: {
                    int diff = o1.getRoleNamespace().compareTo(o2.getRoleNamespace()) * sortDir;
                    if (diff != 0) {
                        return diff;
                    } else {
                        return o1.getRoleName().compareTo(o2.getRoleName()) * sortDir;
                    }
                }
                case CA: return o1.getCaName().compareTo(o2.getCaName()) * sortDir;
                case TOKENTYPE: return StringUtils.defaultString(rm1.getTokenType()).compareTo(StringUtils.defaultString(rm2.getTokenType())) * sortDir;
                case TOKENMATCHVALUE: return StringUtils.defaultString(rm1.getTokenMatchValue()).compareTo(StringUtils.defaultString(rm2.getTokenMatchValue())) * sortDir;
                case DESCRIPTION: return StringUtils.defaultString(rm1.getDescription()).compareTo(StringUtils.defaultString(rm2.getDescription())) * sortDir;
                default:
                    throw new IllegalStateException("Invalid sortBy value");
                }
            }
        });
    }
    
    public String getSortedByRole() { return getSortedBy(SortBy.ROLE); }
    public void sortByRole() { sortBy(SortBy.ROLE, true); }
    public String getSortedByRoleNamespace() { return getSortedBy(SortBy.ROLENAMESPACE); }
    public void sortByRoleNamespace() { sortBy(SortBy.ROLENAMESPACE, true); }
    public String getSortedByCA() { return getSortedBy(SortBy.CA); }
    public void sortByCA() { sortBy(SortBy.CA, true); }
    public String getSortedByTokenType() { return getSortedBy(SortBy.TOKENTYPE); }
    public void sortByTokenType() { sortBy(SortBy.TOKENTYPE, true); }
    public String getSortedByTokenMatchValue() { return getSortedBy(SortBy.TOKENMATCHVALUE); }
    public void sortByTokenMatchValue() { sortBy(SortBy.TOKENMATCHVALUE, true); }
    public String getSortedByDescription() { return getSortedBy(SortBy.DESCRIPTION); }
    public void sortByDescription() { sortBy(SortBy.DESCRIPTION, true); }
    
    public String getSortColumn() {
        return sortBy.name();
    }
    
    public void setSortColumn(final String value) {
        try {
            sortBy = !StringUtils.isBlank(value) ? SortBy.valueOf(value.toUpperCase(Locale.ROOT)) : SortBy.ROLE;
        } catch (IllegalArgumentException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid value for the 'sortColumn' parameter: '" + value + "'");
            }
            sortBy = SortBy.ROLE;
        }
    }
    
    private String getSortedBy(final SortBy sortBy) {
        if (this.sortBy.equals(sortBy)) {
            return isSortAscending() ? "\u25bc" : "\u25b2";
        }
        return "";
    }
    
    /** Set current sort column. Flip the order if the column was already selected. */
    private void sortBy(final SortBy sortBy, final boolean defaultAscending) {
        if (this.sortBy.equals(sortBy)) {
            sortAscending = !isSortAscending();
        } else {
            sortAscending = defaultAscending;
        }
        this.sortBy = sortBy;
        sort();
    }
    
    public boolean isSortAscending() {
        return sortAscending;
    }
    
    public void setSortAscending(final boolean value) {
        sortAscending = value;
    }
    
    public boolean getHasMultipleNamespaces() {
        return hasMultipleNamespaces;
    }
    
    public boolean isOnlyOneRoleAvailable() { return getAvailableRoles().size()==2; } // two including the "any role" choice
    public List<SelectItem> getAvailableRoles() {
        if (availableRoles == null) {
            availableRoles = new ArrayList<>();
            final List<Role> roles = new ArrayList<>(raMasterApiProxyBean.getAuthorizedRoles(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(roles);
            roleIdToNameMap = new HashMap<>();
            roleIdToNamespaceMap = new HashMap<>();
            String lastNamespace = null;
            hasMultipleNamespaces = false;
            for (final Role role : roles) {
                roleIdToNameMap.put(role.getRoleId(), role.getRoleName());
                if (!StringUtils.isEmpty(role.getNameSpace())) {
                    roleIdToNamespaceMap.put(role.getRoleId(), role.getNameSpace());
                }
                // Check if there's more than one namespace. If so the namespaces are shown in the GUI
                if (lastNamespace != null && !lastNamespace.equals(role.getNameSpace())) {
                    hasMultipleNamespaces = true;
                }
                lastNamespace = role.getNameSpace();
            }
            availableRoles.add(new SelectItem(null, raLocaleBean.getMessage("role_members_page_criteria_role_optionany")));
            for (final Role role : roles) {
                final String label = hasMultipleNamespaces ? role.getRoleNameFull() : role.getRoleName();
                availableRoles.add(new SelectItem(role.getRoleId(), label));
            }
        }
        return availableRoles;
    }
    
    public boolean isOnlyOneCaAvailable() { return getAvailableCas().size()==2; } // two including the "any CA" choice
    public List<SelectItem> getAvailableCas() {
        if (availableCas == null) {
            availableCas = new ArrayList<>();
            final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(caInfos, new Comparator<CAInfo>() {
                @Override
                public int compare(final CAInfo caInfo1, final CAInfo caInfo2) {
                    return caInfo1.getName().compareTo(caInfo2.getName());
                }
            });
            caIdToNameMap = new HashMap<>();
            for (final CAInfo caInfo : caInfos) {
                caIdToNameMap.put(caInfo.getCAId(), caInfo.getName());
            }
            availableCas.add(new SelectItem(null, raLocaleBean.getMessage("role_members_page_criteria_ca_optionany")));
            for (final CAInfo caInfo : caInfos) {
                availableCas.add(new SelectItem(caInfo.getCAId(), caInfo.getName()));
            }
        }
        return availableCas;
    }
    
    public boolean isOnlyOneTokenTypeAvailable() { return getAvailableTokenTypes().size()==2; } // two including the "any token type" choice
    public boolean getHasMultipleTokenTypes() { return getAvailableTokenTypes().size()>2; }     // dito
    public List<SelectItem> getAvailableTokenTypes() {
        if (availableTokenTypes == null) {
            if (tokenTypeInfos == null) {
                tokenTypeInfos = raMasterApiProxyBean.getAvailableRoleMemberTokenTypes(raAuthenticationBean.getAuthenticationToken());
            }
            final List<String> tokenTypes = new ArrayList<>(tokenTypeInfos.keySet());
            Collections.sort(tokenTypes);
            availableTokenTypes = new ArrayList<>();
            availableTokenTypes.add(new SelectItem(null, raLocaleBean.getMessage("role_members_page_criteria_tokentype_optionany")));
            for (final String tokenType : tokenTypes) {
                availableTokenTypes.add(new SelectItem(tokenType, raLocaleBean.getMessage("role_member_token_type_" + tokenType)));
            }
        }
        return availableTokenTypes;
    }
    
}
