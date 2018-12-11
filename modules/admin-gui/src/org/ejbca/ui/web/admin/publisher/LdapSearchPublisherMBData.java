package org.ejbca.ui.web.admin.publisher;

import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;

public final class LdapSearchPublisherMBData {

    private String searchBaseDN;
    private String searchFilter;
    
    public String getSearchBaseDN() {
        return searchBaseDN;
    }

    public void setSearchBaseDN(String searchBaseDN) {
        this.searchBaseDN = searchBaseDN;
    }    

    public String getSearchFilter() {
        return searchFilter;
    }

    public void setSearchFilter(String searchFilter) {
        this.searchFilter = searchFilter;
    }
    
    public void setLdapSearchPublisherParameters(final LdapSearchPublisher ldapSearchPublisher) {
        ldapSearchPublisher.setSearchBaseDN(searchBaseDN);
        ldapSearchPublisher.setSearchFilter(searchFilter);
    }
    
}
