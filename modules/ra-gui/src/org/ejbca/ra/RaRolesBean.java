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
import java.util.Locale;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.roles.Role;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;


/**
 * Backing bean for the Roles page
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaRolesBean {
    
    //public static final class RoleMemberGuiInfo 

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaRolesBean.class);
    
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
    
    private List<SelectItem> availableNamespaces = null;
    
    //private String criteriaNamespace;
    private String roleSearchString;
    
    //private RaRequestsSearchResponse lastExecutedResponse = null;
    
    private List<Role> resultsFiltered = new ArrayList<>();
    private boolean hasNamespaces;
    
    private enum SortBy { NAMESPACE, ROLE };
    private SortBy sortBy = SortBy.ROLE;
    private boolean sortAscending = true;
    
    
    public void initialize() {
        searchAndFilterCommon();
    }
    
    public String getRoleSearchString() {
        return roleSearchString;
    }
    
    public void setRoleSearchString(final String roleSearchString) {
        this.roleSearchString = roleSearchString;
    }

/*    public String getCriteriaNamespace() {
        return criteriaNamespace;
    }

    public void setCriteriaNamespace(final String criteriaNamespace) {
        this.criteriaNamespace = criteriaNamespace;
    }*/


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
        // Get data
        // TODO filtering
        resultsFiltered = raMasterApiProxyBean.getAuthorizedRoles(raAuthenticationBean.getAuthenticationToken());
        
        // Check if we should show the namespace column
        hasNamespaces = false;
        for (final Role role : resultsFiltered) {
            if (!StringUtils.isEmpty(role.getNameSpace())) {
                hasNamespaces = true;
            }
        }
        
        sort();
    }
    
    public List<Role> getFilteredResults() {
        return resultsFiltered;
    }
    
    public boolean isMoreResultsAvailable() {
        // TODO
        return false;
    }
    
    public boolean getHasNamespaces() {
        return hasNamespaces;
    }
    
    // Sorting
    private void sort() {
        Collections.sort(resultsFiltered, new Comparator<Role>() {
            @Override
            public int compare(Role o1, Role o2) {
                int sortDir = (isSortAscending() ? 1 : -1);
                switch (sortBy) {
                // TODO locale-aware sorting
                case NAMESPACE: return o1.getNameSpace().compareTo(o2.getNameSpace()) * sortDir;
                case ROLE: return o1.getRoleName().compareTo(o2.getRoleName()) * sortDir;
                default:
                    throw new IllegalStateException("Invalid sortBy value");
                }
            }
        });
    }
    
    public String getSortedByNamespace() { return getSortedBy(SortBy.NAMESPACE); }
    public void sortByNamespace() { sortBy(SortBy.NAMESPACE, true); }
    public String getSortedByRole() { return getSortedBy(SortBy.ROLE); }
    public void sortByRole() { sortBy(SortBy.ROLE, true); }
    
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
    
    
    public boolean isOnlyOneNamespaceAvailable() { return getAvailableNamespaces().size()==2; } // two including the "any namespace" choice
    public List<SelectItem> getAvailableNamespaces() {
        // TODO potentially this method will be slow, because it has to go through all roles
        if (availableNamespaces == null) {
            availableNamespaces = new ArrayList<>();
//            final List<Role> roles = new ArrayList<>(raMasterApiProxyBean.getAuthorizedRoles(raAuthenticationBean.getAuthenticationToken()));
//            Collections.sort(roles, new Comparator<Role>() {
//                @Override
//                public int compare(final Role role1, final Role role2) {
//                    return role1.getRoleName().compareTo(role2.getRoleName());
//                }
//            });
            availableNamespaces.add(new SelectItem(0, raLocaleBean.getMessage("roles_page_criteria_namespace_optionany")));
//            for (final Role role : roles) {
//                availableRoles.add(new SelectItem(role.getRoleId(), "- " + role.getRoleName()));
//            }
        }
        return availableNamespaces;
    }
    
    
}
