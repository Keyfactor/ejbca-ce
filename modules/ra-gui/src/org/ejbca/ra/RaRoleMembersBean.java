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


/**
 * Backing bean for the Role Members page
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRoleMembersBean {
    
    //public static final class RoleMemberGuiInfo 

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
    
    private String genericSearchString;
    private Integer criteriaRoleId;
    private Integer criteriaCaId;
    private String criteriaTokenType;
    private boolean fromRolesPage;
    
    private RaRoleMemberSearchResponse lastExecutedResponse = null;
    
    private List<RaRoleMemberGUIInfo> resultsFiltered = new ArrayList<>();
    private Map<Integer,String> caIdToNameMap;
    private Map<Integer,String> roleIdToNameMap;
    
    private enum SortBy { ROLE, CA, TOKENTYPE, TOKENMATCHVALUE, BINDING };
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
        if (criteriaCaId != null) {
            searchRequest.setCaIds(new ArrayList<>(Arrays.asList(criteriaCaId)));
        }
        if (criteriaRoleId != null) {
            searchRequest.setRoleIds(new ArrayList<>(Arrays.asList(criteriaRoleId)));
        }
        searchRequest.setGenericSearchString(genericSearchString);
        lastExecutedResponse = raMasterApiProxyBean.searchForRoleMembers(raAuthenticationBean.getAuthenticationToken(), searchRequest);
        
        // Add names of CAs and roles
        resultsFiltered = new ArrayList<>();
        for (final RoleMember member : lastExecutedResponse.getRoleMembers()) {
            final String caName = caIdToNameMap.get(member.getTokenIssuerId());
            final String roleName = roleIdToNameMap.get(member.getRoleId());
            resultsFiltered.add(new RaRoleMemberGUIInfo(member, caName, roleName));
        }
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
                case ROLE: return o1.getRoleName().compareTo(o2.getRoleName()) * sortDir;
                case CA: return o1.getCaName().compareTo(o2.getCaName()) * sortDir;
                case TOKENTYPE: return rm1.getTokenType().compareTo(rm2.getTokenType()) * sortDir;
                case TOKENMATCHVALUE: return rm1.getTokenMatchValue().compareTo(rm2.getTokenMatchValue()) * sortDir;
                case BINDING: return rm1.getMemberBindingValue().compareTo(rm2.getMemberBindingValue());
                default:
                    throw new IllegalStateException("Invalid sortBy value");
                }
            }
        });
    }
    
    public String getSortedByRole() { return getSortedBy(SortBy.ROLE); }
    public void sortByRole() { sortBy(SortBy.ROLE, true); }
    public String getSortedByCA() { return getSortedBy(SortBy.CA); }
    public void sortByCA() { sortBy(SortBy.CA, true); }
    public String getSortedByTokenType() { return getSortedBy(SortBy.TOKENTYPE); }
    public void sortByTokenType() { sortBy(SortBy.TOKENTYPE, true); }
    public String getSortedByTokenMatchValue() { return getSortedBy(SortBy.TOKENMATCHVALUE); }
    public void sortByTokenMatchValue() { sortBy(SortBy.TOKENMATCHVALUE, true); }
    public String getSortedByBinding() { return getSortedBy(SortBy.BINDING); }
    public void sortByBinding() { sortBy(SortBy.BINDING, true); }
    
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
    
    
    public boolean isOnlyOneRoleAvailable() { return getAvailableRoles().size()==2; } // two including the "any role" choice
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
            roleIdToNameMap = new HashMap<>();
            for (final Role role : roles) {
                roleIdToNameMap.put(role.getRoleId(), role.getRoleName());
            }
            availableRoles.add(new SelectItem(0, raLocaleBean.getMessage("role_members_page_criteria_role_optionany")));
            for (final Role role : roles) {
                availableRoles.add(new SelectItem(role.getRoleId(), "- " + role.getRoleName()));
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
            availableCas.add(new SelectItem(0, raLocaleBean.getMessage("role_members_page_criteria_ca_optionany")));
            for (final CAInfo caInfo : caInfos) {
                availableCas.add(new SelectItem(caInfo.getCAId(), "- " + caInfo.getName()));
            }
        }
        return availableCas;
    }
    
    public boolean isOnlyOneTokenTypeAvailable() { return getAvailableTokenTypes().size()==2; } // two including the "any token type" choice
    public List<SelectItem> getAvailableTokenTypes() {
        if (availableTokenTypes == null) {
            availableTokenTypes = new ArrayList<>();
            // TODO
            /*final List<Role> roles = new ArrayList<>(raMasterApiProxyBean.getAuthorizedRoles(raAuthenticationBean.getAuthenticationToken()));
            Collections.sort(roles, new Comparator<Role>() {
                @Override
                public int compare(final Role role1, final Role role2) {
                    return role1.getRoleName().compareTo(role2.getRoleName());
                }
            });*/
            availableTokenTypes.add(new SelectItem(0, raLocaleBean.getMessage("role_members_page_criteria_tokentype_optionany")));
            /*for (final Role role : roles) {
                availableRoles.add(new SelectItem(role.getRoleId(), "- " + role.getRoleName()));
            }*/
            availableTokenTypes.add(new SelectItem("X509")); // FIXME remove
        }
        return availableTokenTypes;
    }
    
}
