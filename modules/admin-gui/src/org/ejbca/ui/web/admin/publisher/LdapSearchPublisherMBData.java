package org.ejbca.ui.web.admin.publisher;

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
    
}
