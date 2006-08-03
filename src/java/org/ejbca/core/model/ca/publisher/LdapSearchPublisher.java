package org.ejbca.core.model.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.util.CertTools;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPSearchResults;

public class LdapSearchPublisher extends LdapPublisher {
	
	private static final Logger log = Logger.getLogger(LdapSearchPublisher.class);
	
	
	public static final int TYPE_LDAPSEARCHPUBLISHER = 4;
		
	// Default Values
	protected static final String SEARCHBASEDN = "searchbasedn";
	protected static final String SEARCHFILTER = "searchfilter";
	
	public LdapSearchPublisher() {
		super();
		data.put(TYPE, new Integer(TYPE_LDAPSEARCHPUBLISHER));
		
		setSearchBaseDN("");
		setSearchFilter("");
	}
	
	// Public Methods
	

    /** SearchOldEntity is the only method differing between regular ldap and ldap search publishers.
     *  Aprat from how they find existing users, the publishing works the same.
     */
    protected LDAPEntry searchOldEntity(String username, int ldapVersion, LDAPConnection lc, String dn) throws PublisherException {
        LDAPEntry oldEntry = null; // return value
        int searchScope;
        String searchbasedn;
        boolean attributeOnly;
        String attrs[] = { LDAPConnection.NO_ATTRS };

        // PARTE 1: Search for an existing entry in the LDAP directory
		//  Si existe, sólo se añadirá al DN la parte del certificado (PARTE 2)
		//  Si no existe, se añadirá toda una entrada LDAP nueva (PARTE 2)
		try {
			// connect to the server
			log.debug("Connecting to " + getHostname());
			lc.connect(getHostname(), Integer.parseInt(getPort()));
			// authenticate to the server
			log.debug("Logging in with BIND DN " + getLoginDN());
			lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
			// Filtro estático:
			//searchFilter = "(&(objectclass=person)(uid=" + username + "))";
			String searchFilter = getSearchFilter();
			log.debug("Compiling search filter: " +searchFilter);
			if (username != null) {
				Pattern USER = Pattern.compile("\\$USERNAME", Pattern.CASE_INSENSITIVE);
				searchFilter = USER.matcher(searchFilter).replaceAll(username);
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
			log.debug("Resulting search filter " + searchFilter);
			searchScope = LDAPConnection.SCOPE_SUB;
			attributeOnly = true;
			log.debug("Making SRCH with BaseDN " + getSearchBaseDN() + " and filter " + searchFilter);
			searchbasedn = getSearchBaseDN();
			LDAPSearchResults searchResults = lc.search(searchbasedn, // container to search
					searchScope, // search scope
					searchFilter, // search filter
					attrs, // "1.1" returns entry name only
					attributeOnly); // no attributes are returned
			// try to read the old object
			if (searchResults.getCount() == 1) {
				oldEntry = searchResults.next();
				log.debug("Found one match with filter: "+searchFilter+", match with DN: " + oldEntry.getDN());
				dn = oldEntry.getDN();
			} else {
				if (searchResults.getCount() > 1) {
					log.debug("Found " +searchResults.getCount() +" matches with filter" + searchFilter +
							". Se usara el SubjectDN del certificado como DN para la nueva entrada LDAP: " +dn);
					// Si queremos abortar la operación ante varias coincidencias
					//new PublisherException("LdapSearchPublisher: Se han encontrado " +
					//                       searchResults.getCount() +
					//    " entradas usando el filtro " + searchFilter + ". Se aborta la operacion");
				} else {
					log.debug("No matches found using filter: " +searchFilter + ". Using DN: " + dn);
				}
			}
			// try to read the old object
			try {
				oldEntry = lc.read(dn);
			} catch (LDAPException e) {
				if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
					log.info("No old entry exist for '" + dn + "'.");
				} else {
					log.info("Existe la entrada '" + dn + "', coincidente con el SubjectDN del usuario enrolado.");
				}
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
				log.info("No old entry exist for '" + dn + "'.");
			} else {
				log.error("LDAP ERROR: Error binding to and reading from LDAP server: ", e);
				throw new PublisherException("Error binding to and reading from LDAP server.");
			}
        } catch (UnsupportedEncodingException e) {
            log.error("LDAP ERROR: Can't decode password for LDAP login: "+getLoginPassword(), e);
            throw new PublisherException("Can't decode password for LDAP login: "+getLoginPassword());            
		} finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				log.error("LDAP ERROR: LDAP disconnection failed: ", e);
			}
		}
        return oldEntry;
    }
    
	/**
	 *  Retorna el base de la búsqueda
	 */
	public String getSearchBaseDN() {
		return (String) data.get(SEARCHBASEDN);
	}
	
	/**
	 *  Establece la base de la búsqueda.
	 */
	public void setSearchBaseDN(String searchbasedn) {
		data.put(SEARCHBASEDN, searchbasedn);
	}
	
	/**
	 *  Retorna el filtro de búsqueda
	 */
	public String getSearchFilter() {
		return (String) data.get(SEARCHFILTER);
	}
	
	/**
	 *  Establece el filtro de búsqueda
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
