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

package org.ejbca.core.protocol.msae;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;

@Local
public interface ADConnectionSingletonLocal {

    void updateConnectionProperties(String alias);
    
    public void testConnection(String domain, int port, String loginDN, String loginPassword, boolean useSSL, boolean followLdapReferral,String alias) throws LDAPException;

    public List<MSAutoEnrollmentSettingsTemplate> getCertificateTemplateSettings(String alias);

    public NamingEnumeration<SearchResult> getEntryNamedContext(String searchBase, String searchFilter, SearchControls searchCtls, String alias) throws LDAPException;
    
    default void setLoginDN(final String loginDN, final String alias) {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }
    
    default boolean publishCertificateToLDAP(String distinguishedName, X509Certificate cert, String domain, String alias) throws NamingException {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }
    
    default SearchResult getADDetails(String searchBase, String searchFilter, SearchControls searchCtls, String alias) throws NamingException {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }

    default SearchResult getDomainAndNETBIOS(String distinguishedName, String domain, String alias) throws NamingException {
        throw new UnsupportedOperationException("ADConnection calls are only supported in EJBCA Enterprise");
    }
    
}
