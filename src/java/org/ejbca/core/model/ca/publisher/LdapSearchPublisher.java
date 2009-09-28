package org.ejbca.core.model.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.util.CertTools;
import org.ejbca.util.TCPTool;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

public class LdapSearchPublisher extends LdapPublisher {
	
	private static final Logger log = Logger.getLogger(LdapSearchPublisher.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
	public static final int TYPE_LDAPSEARCHPUBLISHER = 4;

	// Default Values
	protected static final String SEARCHBASEDN = "searchbasedn";
	protected static final String SEARCHFILTER = "searchfilter";
	
	public LdapSearchPublisher() {
		super();
		data.put(TYPE, new Integer(TYPE_LDAPSEARCHPUBLISHER));
		
		setSearchBaseDN("");
		setSearchFilter("");
		
		// By default the LDAP search publisher should not modify any attributes except the certificate
		setModifyExistingAttributes(false);
		setAddNonExistingAttributes(false);
	}
	
	// Public Methods
	

    /** SearchOldEntity is the only method differing between regular ldap and ldap search publishers.
     *  Apart from how they find existing users, the publishing works the same.
     *  
	 *  @param dn the DN from the certificate, can be used to extract search information or a LDAP DN
     */
    protected LDAPEntry searchOldEntity(String username, int ldapVersion, LDAPConnection lc, String dn, String email) throws PublisherException {
        LDAPEntry oldEntry = null; // return value

		// Try all the listed servers
		Iterator servers = getHostnameList().iterator();
		boolean connectionFailed;
		do {
			connectionFailed = false;
			String currentServer = (String) servers.next();
	        // PARTE 1: Search for an existing entry in the LDAP directory
			//  If it exists, s�lo se a�adir� al DN la parte del certificado (PARTE 2)
			//  if not exist, se a�adir� toda una entrada LDAP nueva (PARTE 2)
			try {
				TCPTool.probeConnectionLDAP(currentServer, Integer.parseInt(getPort()), getConnectionTimeOut());	// Avoid waiting for halfdead-servers
				// connect to the server
				log.debug("Connecting to " + currentServer);
				lc.connect(currentServer, Integer.parseInt(getPort()));
				// authenticate to the server
				log.debug("Logging in with BIND DN " + getLoginDN());
				lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"), ldapBindConstraints);
				//searchFilter = "(&(objectclass=person)(uid=" + username + "))";
				String searchFilter = getSearchFilter();
				if (log.isDebugEnabled()) {
					log.debug("Compiling search filter: " +searchFilter+", from dn: "+dn);
				}
				if (username != null) {
					Pattern USER = Pattern.compile("\\$USERNAME", Pattern.CASE_INSENSITIVE);
					searchFilter = USER.matcher(searchFilter).replaceAll(username);
				}
				if (email != null) {
					Pattern EMAIL = Pattern.compile("\\$EMAIL", Pattern.CASE_INSENSITIVE);
					searchFilter = EMAIL.matcher(searchFilter).replaceAll(email);
				}
				if (CertTools.getPartFromDN(dn, "CN") != null) {
					Pattern CN = Pattern.compile("\\$CN", Pattern.CASE_INSENSITIVE);
					searchFilter = CN.matcher(searchFilter).replaceAll(CertTools.getPartFromDN(dn, "CN"));
				}
				if (CertTools.getPartFromDN(dn, "O") != null) {
					Pattern O = Pattern.compile("\\$O", Pattern.CASE_INSENSITIVE);
					searchFilter = O.matcher(searchFilter).replaceAll(CertTools.getPartFromDN(dn, "O"));
				}
				if (CertTools.getPartFromDN(dn, "OU") != null) {
					Pattern OU = Pattern.compile("\\$OU", Pattern.CASE_INSENSITIVE);
					searchFilter = OU.matcher(searchFilter).replaceAll(CertTools.getPartFromDN(dn, "OU"));
				}
				if (CertTools.getPartFromDN(dn, "C") != null) {
					Pattern C = Pattern.compile("\\$C", Pattern.CASE_INSENSITIVE);
					searchFilter = C.matcher(searchFilter).replaceAll(CertTools.getPartFromDN(dn, "C"));
				}
				if (CertTools.getPartFromDN(dn, "UID") != null) {
					Pattern C = Pattern.compile("\\$UID", Pattern.CASE_INSENSITIVE);
					searchFilter = C.matcher(searchFilter).replaceAll(CertTools.getPartFromDN(dn, "UID"));
				}
				log.debug("Resulting search filter '" + searchFilter+"'.");
				log.debug("Making SRCH with BaseDN '" + getSearchBaseDN() + "' and filter '" + searchFilter+"'.");
				String searchbasedn = getSearchBaseDN();
				int searchScope = LDAPConnection.SCOPE_SUB;
		        String attrs[] = { LDAPConnection.NO_ATTRS };
				boolean attributeTypesOnly = true;
				LDAPSearchResults searchResults = lc.search(searchbasedn, // container to search
						searchScope, // search scope
						searchFilter, // search filter
						attrs, // "1.1" returns entry name only
						attributeTypesOnly,
						ldapSearchConstraints); // no attribute values are returned
				// try to read the old object
				if (log.isDebugEnabled()) {
					log.debug("serachResults contains entries: "+searchResults.hasMore());
				}
				if (searchResults.hasMore()) {
					oldEntry = searchResults.next();
					dn = oldEntry.getDN();
					if (searchResults.hasMore()) {
						log.debug("Found more than one matches with filter '" + searchFilter +
								"'. Using the first match with LDAP entry with DN: " +oldEntry.getDN());
					} else {
						log.debug("Found one match with filter: '"+searchFilter+"', match with DN: " + oldEntry.getDN());
					}
				} else {
					log.debug("No matches found using filter: '" +searchFilter + "'. Using DN: " + dn);
				}
				// try to read the old object
				try {
					oldEntry = lc.read(dn, ldapSearchConstraints);
				} catch (LDAPException e) {
					if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
						String msg = intres.getLocalizedMessage("publisher.noentry", dn);
						log.info(msg);
					} else {
						String msg = intres.getLocalizedMessage("publisher.infoexists", dn);
						log.info(msg);
					}
				}
			} catch (LDAPException e) {
				if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
					String msg = intres.getLocalizedMessage("publisher.noentry", dn);
					log.info(msg);
				} else {
					connectionFailed = true;
					if (servers.hasNext()) {
						log.debug("Failed to publish to " + currentServer + ". Trying next in list.");
					} else {
		    			String msg = intres.getLocalizedMessage("publisher.errorldapbind", e.getMessage());
		                log.error(msg, e);
						throw new PublisherException(msg);
					}
				}
	        } catch (UnsupportedEncodingException e) {
				String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
	            throw new PublisherException(msg);            
			} finally {
				// disconnect with the server
				try {
					lc.disconnect(ldapDisconnectConstraints);
				} catch (LDAPException e) {
					String msg = intres.getLocalizedMessage("publisher.errordisconnect");
					log.error(msg, e);
				}
			}
		} while (connectionFailed && servers.hasNext()) ;
        return oldEntry;
    }
    
	/**
	 *  Retorna el base de la b�squeda
	 */
	public String getSearchBaseDN() {
		return (String) data.get(SEARCHBASEDN);
	}
	
	/**
	 *  Establece la base de la b�squeda.
	 */
	public void setSearchBaseDN(String searchbasedn) {
		data.put(SEARCHBASEDN, searchbasedn);
	}
	
	/**
	 *  Retorna el filtro de b�squeda
	 */
	public String getSearchFilter() {
		return (String) data.get(SEARCHFILTER);
	}
	
	/**
	 *  Establece el filtro de b�squeda
	 */
	public void setSearchFilter(String searchfilter) {
		data.put(SEARCHFILTER, searchfilter);
	}
	
	
	// Private methods
	
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		LdapSearchPublisher clone = new LdapSearchPublisher();
		HashMap clonedata = (HashMap) clone.saveData();
		
		Iterator i = (data.keySet()).iterator();
		while (i.hasNext()) {
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}
		
		clone.loadData(clonedata);
		return clone;
	}
		
}
