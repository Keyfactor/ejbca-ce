/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.apache.log4j.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class ADObject {
    private static final Logger log = Logger.getLogger(ADObject.class);
    private String sAMAccountName;
    private String distinguishedName;
    private String mail;
    private String cn;
    private String dnsHostName;
    private String userPrincipalName;
    private byte[] objectGUID;
    private String dnsRoot;
    private String nETBIOSName;

    private ADConnection adConnection;

    ADObject(ADConnection adConnection) {
        this.adConnection = adConnection;
    }

    void getADDetails(TemplateSettings ts, String searchBase, String sAMAccountName, String domain) throws EnrollmentException, NamingException {
        // Create the search controls
        SearchControls searchCtls = new SearchControls();

        // Specify the attributes to return
        final String returnedAtts[] = {"sAMAccountName", "cn", "mail", "dnsHostName", "userPrincipalName",
                "distinguishedName", "objectGUID"};
        searchCtls.setReturningAttributes(returnedAtts);

        // Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        searchCtls.setReturningObjFlag(false);

        // specify the LDAP search filter
        final String searchFilter = "(&(objectClass=user)(sAMAccountName=" + sAMAccountName + "))";

        if (log.isDebugEnabled()) {
            log.debug("Looking up Active Directory details for: " + sAMAccountName);
        }
        if (log.isTraceEnabled()) {
            log.trace("searchBase: " + searchBase);
            log.trace("searchFilter: " + searchFilter);
        }

        final SearchResult sr = adConnection.getADDetails(searchBase, searchFilter, searchCtls, domain);
        updateObjectAttributes(sr);

        if (ts.isInclude_spn_in_san() || ts.isInclude_netbios_in_san() || ts.isInclude_domain_in_san()) {
            SearchResult domainAndNETBIOS = getDomainAndNETBIOS(distinguishedName, domain);
            updateDomain(domainAndNETBIOS);
            updateNETBIOS(domainAndNETBIOS);
        }
    }

    private void updateObjectAttributes(SearchResult sr) throws EnrollmentException {
        final Attributes attrs = sr.getAttributes();

        try {
            cn = attrs.get("cn") != null ? attrs.get("cn").get().toString() : null;
            sAMAccountName = attrs.get("sAMAccountName") != null ? attrs.get("sAMAccountName").get().toString() : null;
            mail = attrs.get("mail") != null ? attrs.get("mail").get().toString() : null;
            dnsHostName = attrs.get("dnsHostName") != null ? attrs.get("dnsHostName").get().toString() : null;
            userPrincipalName = attrs.get("userPrincipalName") != null ? attrs.get("userPrincipalName").get().toString()
                    : null;
            distinguishedName = attrs.get("distinguishedName") != null ? attrs.get("distinguishedName").get().toString()
                    : null;
            objectGUID = attrs.get("objectGUID") != null ? (byte[]) attrs.get("objectGUID").get() : null;
        } catch (NamingException ne) {
            throw new EnrollmentException("Error setting AD Object attributes: " + ne.getMessage());
        }
    }

    /**
     * Gets domain name and NETBIOS name from Active Directory forest
     * configuration container.
     */
    private SearchResult getDomainAndNETBIOS(String distinguishedName, String domain) throws EnrollmentException, NamingException {
        return adConnection.getDomainAndNETBIOS(distinguishedName, domain);
    }

    private void updateDomain(SearchResult sr) throws EnrollmentException {
        final Attributes attrs = sr.getAttributes();

        try {
            dnsRoot = attrs.get("dnsRoot").get().toString();
        } catch (NamingException ne) {
            throw new EnrollmentException("Error setting AD Object attributes: " + ne.getMessage());
        }
    }

    private void updateNETBIOS(SearchResult sr) throws EnrollmentException {
        final Attributes attrs = sr.getAttributes();

        try {
            nETBIOSName = attrs.get("nETBIOSName").get().toString();
        } catch (NamingException ne) {
            throw new EnrollmentException("Error setting AD Object attributes: " + ne.getMessage());
        }
    }

    public String getDnsRoot() {
        return dnsRoot;
    }

    public String getnETBIOSName() {
        return nETBIOSName;
    }

    public String getsAMAccountName() {
        return sAMAccountName;
    }

    public String getDistinguishedName() {
        return distinguishedName;
    }

    public String getMail() {
        return mail;
    }

    public String getCn() {
        return cn;
    }

    public String getDnsHostName() {
        return dnsHostName;
    }

    public String getUserPrincipalName() {
        return userPrincipalName;
    }

    public byte[] getObjectGUID() {
        return objectGUID;
    }
}
