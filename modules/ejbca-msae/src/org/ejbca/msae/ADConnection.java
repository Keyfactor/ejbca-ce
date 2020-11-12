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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

/**
 * @version $Id: ADConnection.java 25133 2017-01-27 12:19:09Z anatom $
 */
class ADConnection {

    private static final Logger log = Logger.getLogger(ADConnection.class);

    // Properties
    private static final String PROPERTY_USESSL = "usessl";
    private static final String PROPERTY_PORT = "port";
    private static final String PROPERTY_LOGINDN = "logindn";
    private static final String PROPERTY_LOGINPASSWORD = "loginpassword";

    // Default values
    private static final String DEFAULT_PORT = "389";

    private boolean useSSL;
    private String port;
    private String loginDN;
    private String loginPassword;

    private DirContext ldapContext;

    ADConnection(PublisherProperties msaes) {
        useSSL = Boolean.parseBoolean(msaes.getUSESSL());
        port = msaes.getPORT();
        loginDN = msaes.getLOGINDN();
        loginPassword = msaes.getLOGINPASSWORD();
    }

    private void initConnection(String hostname) throws EnrollmentException {
        try {
            Hashtable<String, String> ldapEnv = new Hashtable<>();
            ldapEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            //Enable connection pooling
            ldapEnv.put("com.sun.jndi.ldap.connect.pool", "true");
            ldapEnv.put(Context.PROVIDER_URL, "ldap://" + hostname + ":" + port);
            ldapEnv.put(Context.SECURITY_AUTHENTICATION, "simple");
            ldapEnv.put(Context.SECURITY_PRINCIPAL, loginDN);
            ldapEnv.put(Context.SECURITY_CREDENTIALS, loginPassword);
            ldapEnv.put("java.naming.ldap.attributes.binary", "objectGUID");
            if(useSSL) {
                ldapEnv.put(Context.SECURITY_PROTOCOL, "ssl");
            }
            // ldapEnv.put(Context.SECURITY_PROTOCOL, "simple");
            ldapContext = new InitialDirContext(ldapEnv);
        } catch(NamingException ne) {
            throw new EnrollmentException("Error creating AD connection: " + ne.getMessage());
        }
    }

    SearchResult getADDetails(String searchBase, String searchFilter, SearchControls searchCtls, String domain) throws EnrollmentException, NamingException {
        final NamingEnumeration<SearchResult> answer = getEntryNamedContext(searchBase, searchFilter, searchCtls, domain);
        final SearchResult sr = ldapLookupSearchResult(answer);
        return sr;
    }

    private NamingEnumeration<SearchResult> getEntryNamedContext(String searchBase, String searchFilter, SearchControls searchCtls, String domain) throws EnrollmentException {
        initConnection(domain);
        try {
            // Search for objects using the filter
            final NamingEnumeration<SearchResult> answer = ldapContext.search(searchBase, searchFilter, searchCtls);
            if (null == answer) {
                throw new EnrollmentException("Active Directory search returned no results.");
            }
            return answer;
        } catch (NamingException ne) {
            throw new EnrollmentException("Searching for entry in Active Directory failed: " + ne.getMessage());
        } finally {
            closeConnection();
        }
    }

    private SearchResult ldapLookupSearchResult(NamingEnumeration<SearchResult> answer) throws EnrollmentException {
        if (answer.hasMoreElements()) {
            try {
                final SearchResult sr = answer.next();
                if (log.isDebugEnabled()) {
                    log.debug("AD Search Result: " + sr);
                }
                if(answer.hasMoreElements()) {
                    log.error("More than 1 result was found.");
                }
                return sr;
            } catch (NamingException ne) {
                throw new EnrollmentException("Getting elements from search results failed: " + ne.getMessage());
            }
        } else {
            throw new EnrollmentException("Active Directory search result was empty.");
        }
    }

    /**
     * Gets domain name and NETBIOS name from Active Directory forest
     * configuration container.
     */
    SearchResult getDomainAndNETBIOS(String distinguishedName, String domain) throws EnrollmentException, NamingException {
        // Create the search controls
        SearchControls searchCtls = new SearchControls();

        // Specify the attributes to return
        final String returnedAtts[] = {"dnsRoot", "nETBIOSName"};
        searchCtls.setReturningAttributes(returnedAtts);

        // Specify the search scope
        searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        if (distinguishedName == null) {
            throw new EnrollmentException("No distinguishedName was found.");
        }

        // get the domain dns name and netbios name
        final String nCName = distinguishedName.substring(distinguishedName.indexOf("DC="));
        final String configurationNamingContext = getConfigurationNamingContext(domain);

        log.debug("Configuration naming context is: " + configurationNamingContext);
        if (null == configurationNamingContext) {
            throw new EnrollmentException("Could not get configuration naming context from: " + distinguishedName);
        }
        final String searchBase = "CN=Partitions," + configurationNamingContext;
        final String searchFilter = "(&(nCName=" + nCName + "))";

        log.debug("Searching for domain DNS name and NETBIOS name with '" + searchBase + "'");

        // Search for objects using the filter
        final NamingEnumeration<SearchResult> answer = getEntryNamedContext(searchBase, searchFilter, searchCtls, domain);
        final SearchResult sr = ldapLookupSearchResult(answer);

        return sr;
    }

    /**
     * Auto detect configuration naming context from the loginDN user.
     *
     * @return configurationNamingContext
     * @throws EnrollmentException
     */
    private String getConfigurationNamingContext(String domain) throws EnrollmentException {
        initConnection(domain);
        String configurationNamingContext = null;
        try {
            final Attributes attributes = ldapContext.getAttributes("", new String[]{"configurationNamingContext"});
            final Attribute attribute = attributes.get("configurationNamingContext");
            if (null != attribute) {
                configurationNamingContext = attribute.getAll().next().toString();
            }
        } catch(NamingException ne) {
            throw new EnrollmentException("Error getting Configuration Naming Context: " + ne.getMessage());
        } finally {
            closeConnection();
        }
        return configurationNamingContext;
    }

    /**
     * Publish issued certificate to Active Directory userCertificate object
     *
     * @param cert X509 certificate to publish
     * @return true if publishing was successful, false if publishing fails or
     * error getting encoded value of cert
     */
    boolean publishCertificateToLDAP(String distinguishedName, X509Certificate cert, String domain) throws EnrollmentException, NamingException {
        ModificationItem[] mods = new ModificationItem[1];
        byte[] encodedCert;
        try {
            encodedCert = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new EnrollmentException("Certificate Encoding Error: " + e.getMessage());
        }

        mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute("userCertificate", encodedCert));
        initConnection(domain);
        try {
            ldapContext.modifyAttributes(distinguishedName, mods);
        } catch (NamingException ne) {
            throw new EnrollmentException(
                    "Modify userCertificate attribute failed for " + distinguishedName + ": " + ne.getMessage());
        } finally {
            closeConnection();
        }

        return true;
    }

    private void closeConnection() throws EnrollmentException {
        try {
            ldapContext.close();
        } catch(NamingException ne) {
            throw new EnrollmentException("Could not close AD connection: " + ne.getMessage());
        }
    }

    public String getPort() {
        return port;
    }

    public boolean isUseSSL() {
        return useSSL;
    }

    public String getLoginDN() {
        return loginDN;
    }
}
