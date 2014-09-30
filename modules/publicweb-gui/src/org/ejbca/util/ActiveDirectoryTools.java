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
package org.ejbca.util;

import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.config.GlobalConfiguration;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchResults;

/**
 * @version $Id$
 */
public class ActiveDirectoryTools {
	private static final Logger log = Logger.getLogger(ActiveDirectoryTools.class);
    //private static final InternalResources intres = InternalResources.getInstance();

	/**
     * Return the DN of the requested user.
     * 
	 *@param globalConfiguration contains Active Directory configuration for autenrollment used in this method
	 *@param usernameShort is the SAMUserAccountName e.g. "Administrator" 
	 */
	public static String getUserDNFromActiveDirectory(GlobalConfiguration globalConfiguration, String usernameShort) {
		String activeDirectoryServer = globalConfiguration.getAutoEnrollADServer();
		int activeDirectoryPort = globalConfiguration.getAutoEnrollADPort();
		boolean useSSLConnection = globalConfiguration.getAutoEnrollSSLConnection();	
		String activeDirectoryUserDN = globalConfiguration.getAutoEnrollConnectionDN();
		String activeDirectoryUserPassword = globalConfiguration.getAutoEnrollConnectionPwd();
		String userSearchBaseDN = globalConfiguration.getAutoEnrollBaseDNUser();
		return ActiveDirectoryTools.getSubjectDNFromUserInAD(activeDirectoryServer, activeDirectoryPort, useSSLConnection, activeDirectoryUserDN, activeDirectoryUserPassword,
				userSearchBaseDN, usernameShort);
	}
	
	/**
     * Return the DN of the requested user.
     * 
     * @param serverAddress host of the Active Directory server
	 * @param port can be set to 0 to use the default port (389 or 636 for SSL)
     * @param useSSL if the AD can handle this
     * @param connectionDN is the connectors DN. E.g. "cn=Administrator,cn=Users,dc=org,dc=local"
     * @param connectionPassword is the connectors password
     * @param baseDN is base DN of where to look for the user. E.g. "cn=Users,dc=org,dc=local"
     * @param username is the SAMAccountName for the user to look for
     * @return the full DN of the user
     */
	static public String getSubjectDNFromUserInAD(String serverAddress, int port, boolean useSSL,
			String connectionDN, String connectionPassword, String baseDN, String username) {
		String requestedDN = null;
		LDAPConnection lc = getNewConnection(serverAddress, port, useSSL, connectionDN, connectionPassword);
		if (lc == null) {
			return null;
		}
		LDAPEntry entry = null;
		try {
			String searchFilter = "(&(objectClass=person)(sAMAccountName=" + username + "))";
	        String[] attrs = { LDAPConnection.NO_ATTRS };
	        // Search recursively, but don't return any attributes for found objects
			LDAPSearchResults searchResults = lc.search(baseDN, LDAPConnection.SCOPE_SUB, searchFilter, attrs, true);
			if (searchResults.hasMore()) {
				// Re-read the object to get the attributes now
				requestedDN = searchResults.next().getDN();
				// List all props just for fun.. (TODO: Remove this..)
				entry = lc.read(requestedDN);
				if (entry != null) {
					@SuppressWarnings("unchecked")
                    Iterator<LDAPAttribute> iter = entry.getAttributeSet().iterator();
					while (iter.hasNext()) {
						log.info(".. " + iter.next().toString().replaceAll("[^A-Za-z]", ""));
					}
				}
			} else {
				log.info("No matches found using filter: '" +searchFilter + "'.");
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
				log.info("No such entry exist.");
			} else {
				log.error("Unknown AD error", e);
			}
		} finally {
			// disconnect with the server
			disconnect(lc);
		}
		return requestedDN;
	}

	/**
	 * Create new LDAP connection to Active Directory server.
	 * @param port can be set to 0 to use the default port (389 or 636 for SSL)
	 */
	private static LDAPConnection getNewConnection(String serverAddress, int port, boolean useSSL, String connectionDN, String connectionPassword) {
		LDAPConnection lc = null;
		int ldapPort = port;
		if (useSSL) {
			lc = new LDAPConnection(new LDAPJSSESecureSocketFactory());
			if (ldapPort == 0) {
				ldapPort = LDAPConnection.DEFAULT_SSL_PORT;	// Port 636
			}
		} else {
			lc = new LDAPConnection();
			if (ldapPort == 0) {
				ldapPort = LDAPConnection.DEFAULT_PORT;	// Port 389
			}
		}
		try {
			// connect to the server
			lc.connect(serverAddress, ldapPort);
			// authenticate to the server
			lc.bind(LDAPConnection.LDAP_V3, connectionDN, connectionPassword.getBytes());
		} catch (LDAPException e) {
			log.error("Error during AD bind", e);
			disconnect(lc);
			lc = null;
		}
		return lc;
	}

	/**
	 * Clsoe and clean up existing connection.
	 */
	private static void disconnect(LDAPConnection lc) {
		try {
			lc.disconnect();
		} catch (LDAPException e) {
			log.error("Error during AD disconnect", e);
		}
	}
			

}
