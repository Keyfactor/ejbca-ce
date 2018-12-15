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

package org.ejbca.ui.web.admin.publisher;

import java.io.Serializable;

import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;

/**
 * Class keeping data for ldap search publisher.
 * 
 * @version $Id$
 *
 */
public final class LdapSearchPublisherMBData implements Serializable {

    private static final long serialVersionUID = 1L;
    private String searchBaseDN;
    private String searchFilter;
    
    public LdapSearchPublisherMBData(final LdapSearchPublisher ldapSearchPublisher) {
        initializeData(ldapSearchPublisher);
    }
    
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
    
    private void initializeData(final LdapSearchPublisher ldapSearchPublisher) {
        this.searchBaseDN = ldapSearchPublisher.getSearchBaseDN();
        this.searchFilter = ldapSearchPublisher.getSearchFilter();
    }
    
}
