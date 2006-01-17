package org.ejbca.core.model.ca.publisher;

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.CertTools;


import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchResults;

public class LdapSearchPublisher extends LdapPublisher {
	
	private static final Logger log = Logger.getLogger(LdapSearchPublisher.class);
	
	
	public static final float LATEST_VERSION = 1;
	
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
	
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */
	public boolean storeCertificate(Admin admin, Certificate incert,
			String username, String password, String cafp, int status, int type,
			ExtendedInformation extendedinformation) throws PublisherException {
		log.debug("LdapSearchPublisher: >storeCertificate(username=" + username +")");
		int searchScope = LDAPConnection.SCOPE_ONE;
		int ldapVersion = LDAPConnection.LDAP_V3;
		String searchbasedn = getSearchBaseDN();
		boolean attributeOnly = true;
		String attrs[] = { LDAPConnection.NO_ATTRS };
		
		LDAPConnection lc = null;
		if (getUseSSL()) {
			lc = new LDAPConnection(new LDAPJSSESecureSocketFactory());
		} else {
			lc = new LDAPConnection();
		}
		
		String dn = null;
		String certdn = null;
		try {
			// Extract the users DN from the cert.
			certdn = CertTools.getSubjectDN( (X509Certificate) incert);
			log.debug( "LdapSearchPublisher: Construyendo DN a partir del formulario para " + username);
			dn = constructLDAPDN(certdn);
			log.debug("LdapSearchPublisher: LDAP DN for user " +username +" is " + dn);
		} catch (Exception e) {
			log.error("LdapSearchPublisher: Error decoding input certificate: ", e);
			throw new PublisherException("Error decoding input certificate.");
		}
		
		// Extract the users email from the cert.
		String email = CertTools.getEMailAddress((X509Certificate)incert);
		
		// Check if the entry is already present, first, defined filter will be used. As second option, it check if the entry had been created in other session. We will update it with the new certificate and update LDAP entry if we apporve it
		LDAPEntry oldEntry = null;
		
		// PARTE 1: Search for an existing entry in the LDAP directory
		//  Si existe, sólo se añadirá al DN la parte del certificado (PARTE 2)
		//  Si no existe, se añadirá toda una entrada LDAP nueva (PARTE 2)
		try {
			// connect to the server
			log.debug("LdapSearchPublisher: Conectando con " + getHostname());
			lc.connect(getHostname(), Integer.parseInt(getPort()));
			// authenticate to the server
			log.debug("LdapSearchPublisher: Realizando BIND con DN " + getLoginDN());
			lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
			// Filtro estático:
			//searchFilter = "(&(objectclass=person)(uid=" + username + "))";
			String searchFilter = getSearchFilter();
			log.debug("LdapSearchPublisher: Usando filtro de busqueda " +searchFilter);
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
			log.debug("LdapSearchPublisher: Resulting search filter " + searchFilter);
			searchScope = LDAPConnection.SCOPE_SUB;
			attributeOnly = true;
			log.debug("LdapSearchPublisher: Making SRCH with BaseDN " + getSearchBaseDN() + " and filter " + searchFilter);
			searchbasedn = getSearchBaseDN();
			LDAPSearchResults searchResults = lc.search(searchbasedn, // container to search
					searchScope, // search scope
					searchFilter, // search filter
					attrs, // "1.1" returns entry name only
					attributeOnly); // no attributes are returned
			// try to read the old object
			if (searchResults.getCount() == 1) {
				oldEntry = searchResults.next();
				log.debug("LdapSearchPublisher: Found one match with filter: "+searchFilter+", match with DN: " + oldEntry.getDN());
				dn = oldEntry.getDN();
			} else {
				if (searchResults.getCount() > 1) {
					log.debug("LdapSearchPublisher: Found " +searchResults.getCount() +" matches with filter" + searchFilter +
							". Se usara el SubjectDN del certificado como DN para la nueva entrada LDAP: " +dn);
					// Si queremos abortar la operación ante varias coincidencias
					//new PublisherException("LdapSearchPublisher: Se han encontrado " +
					//                       searchResults.getCount() +
					//    " entradas usando el filtro " + searchFilter + ". Se aborta la operacion");
				} else {
					log.debug("LdapSearchPublisher: No matches found using filter: " +searchFilter + ". Using DN: " + dn);
				}
			}
			// try to read the old objectLeo, compuesta por la plantilla
			try {
				oldEntry = lc.read(dn);
			} catch (LDAPException e) {
				if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
					log.info("LdapSearchPublisher: No old entry exist for '" + dn + "'.");
				} else {
					log.info("LdapSearchPublisher: Existe la entrada '" + dn + "', coincidente con el SubjectDN del usuario enrolado.");
				}
			}
		} catch (LDAPException e) {
			if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
				log.info("LdapSearchPublisher: No old entry exist for '" + dn + "'.");
			} else {
				log.error("LdapSearchPublisher: Error binding to and reading from LDAP server: ", e);
				throw new PublisherException("LdapSearchPublisher: Error binding to and reading from LDAP server.");
			}
        } catch (UnsupportedEncodingException e) {
            log.error("Can't decode password for LDAP login: "+getLoginPassword(), e);
            throw new PublisherException("Can't decode password for LDAP login: "+getLoginPassword());            
		} finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				log.error("LdapSearchPublisher: LDAP disconnection failed: ", e);
			}
		}
		
		// PARTE 2: Create LDAP entry
		//  Se usarán los parámetros del LDAP, si el usuario existiera.
		//  Si no existiera la entrada, se usarán los parámetros introducidos para el certificado.
		LDAPEntry newEntry = null;
		ArrayList modSet = new ArrayList();
		LDAPAttributeSet attributeSet = null;
		String attribute = null;
		String objectclass = null;
		
		if (type == CertificateDataBean.CERTTYPE_ENDENTITY) {
			log.debug("LdapSearchPublisher: Publishing end user certificate to " +getHostname());
			// Llevo a cabo la elaboración de la entrada LDAP resultante final con los atributos dados mediante el subjectDN del certificado
			
			if ( (oldEntry != null) && getModifyExistingUsers()) {
				// TODO: Are we the correct type objectclass?
				log.debug("LdapSearchPublisher: Se reajusta informacion LDAP de " + getHostname() + ". Prevalece la info del subject DN del certificado.");
				modSet = getModificationSet(oldEntry, certdn, true, true);
			} else {
				if (oldEntry != null) {
					// Omito los cambios en el modSet a aplicar a la entrada LDAP
					log.debug("LdapSearchPublisher: Se omite informacion del subject DN del certificado. Prevalece informacion LDAP de " +getHostname());
					modSet = getModificationSet(oldEntry, certdn, false, true);
				} else {
					objectclass = getUserObjectClass(); // just used for logging
					attributeSet = getAttributeSet(incert, getUserObjectClass(), certdn, true, true, password, extendedinformation);
					log.debug("LdapSearchPublisher: Se creara una nueva entrada con las clases " + objectclass);
				}
			}
			// Llevo a cabo la elaboración de la entrada LDAP resultante final con el atributo mail
			if (email != null) {
				LDAPAttribute mailAttr = new LDAPAttribute("mail", email);
				if (oldEntry == null) {
					attributeSet.add(mailAttr);
					log.debug("LdapSearchPublisher: Including email in the new entry: "+email);
				} else {
					if (getModifyExistingUsers()) {
						modSet.add(new LDAPModification(LDAPModification.REPLACE, mailAttr));
						log.debug("LdapSearchPublisher: Changing information in ldap, replacing email with new value: " +email);
					} else {
						log.debug("LdapSearchPublisher: not changing existing email.");
					}
				}
			}
			
			// Llevo a cabo la elaboración de la entrada LDAP resultante final con el atributo userCertificate
			try {
				attribute = getUserCertAttribute();
				LDAPAttribute certAttr = new LDAPAttribute(getUserCertAttribute(), incert.getEncoded());
				if (oldEntry != null) {
					modSet.add(new LDAPModification(LDAPModification.REPLACE, certAttr));
					log.debug("LdapSearchPublisher: Se reajusta informacion del LDAP. Se actualiza el certificado del usuario: " +certAttr);
				} else {
					attributeSet.add(certAttr);
					log.debug("LdapSearchPublisher: Se incluira el certificado del usuario:" + certAttr);
				}
			} catch (CertificateEncodingException e) {
				log.error("LdapSearchPublisher: Error encoding certificate when storing in LDAP: ",e);
				throw new PublisherException(
				"Error encoding certificate when storing in LDAP.");
			}
		} else if ( (type == CertificateDataBean.CERTTYPE_SUBCA) || (type == CertificateDataBean.CERTTYPE_ROOTCA)) {
			log.debug("LdapSearchPublisher: Publishing CA certificate to " +getHostname());
			
			if (oldEntry != null) {
				modSet = getModificationSet(oldEntry, certdn, false, false);
			} else {
				objectclass = getCAObjectClass(); // just used for logging
				attributeSet = getAttributeSet(incert, getCAObjectClass(), certdn, true, false, password, extendedinformation);
			}
			try {
				attribute = getCACertAttribute();
				LDAPAttribute certAttr = new LDAPAttribute(getCACertAttribute(), incert.getEncoded());
				if (oldEntry != null) {
					modSet.add(new LDAPModification(LDAPModification.REPLACE, certAttr));
				} else {
					attributeSet.add(certAttr);
					// Also create using the crlattribute, it may be required
					LDAPAttribute crlAttr = new LDAPAttribute(getCRLAttribute(), fakecrl);
					attributeSet.add(crlAttr);
					// Also create using the arlattribute, it may be required
					LDAPAttribute arlAttr = new LDAPAttribute(getARLAttribute(), fakecrl);
					attributeSet.add(arlAttr);
					log.debug("Added (fake) attribute for CRL and ARL.");
				}
			} catch (CertificateEncodingException e) {
				log.error("LdapSearchPublisher: Error encoding certificate when storing in LDAP: ", e);
				throw new PublisherException("Error encoding certificate when storing in LDAP.");
			}
		} else {
			log.info("LdapSearchPublisher: Certificate of type '" + type +"' will not be published.");
			throw new PublisherException("Certificate of type '" + type +"' will not be published.");
		}
		
		// PARTE 3: MODIFICATION AND ADDITION OF NEW USERS
		//  Una vez creada la entrada (nueva o modificada), se escribe e el LDAP
		try {
			lc.connect(getHostname(), Integer.parseInt(getPort()));
			// authenticate to the server
			lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
			// Add or modify the entry
			if (oldEntry != null) {
                LDAPModification[] mods = new LDAPModification[modSet.size()]; 
                mods = (LDAPModification[])modSet.toArray(mods);
				lc.modify(dn, mods);
				log.info("LdapSearchPublisher: Modified object: " + dn + " successfully.");
			} else {
				if (this.getCreateNonExisingUsers()) {
						newEntry = new LDAPEntry(dn, attributeSet);
						lc.add(newEntry);
						log.info("LdapPublisher: Added object: " + dn + " successfully.");
				}
			}
		} catch (LDAPException e) {
			log.error("Error storing certificate (" + attribute + ") in LDAP (" + objectclass + ") for DN (" + dn + "): ", e);  
			throw new PublisherException("Error storing certificate (" + attribute + ") in LDAP (" + objectclass + ") for DN (" + dn + ").");            
        } catch (UnsupportedEncodingException e) {
            log.error("Can't decode password for LDAP login: "+getLoginPassword(), e);
            throw new PublisherException("Can't decode password for LDAP login: "+getLoginPassword());            
		} finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				log.error("LdapSearchPublisher: LDAP disconnection failed: ", e);
			}
		}
		log.debug("<storeCertificate()");
		return true;
	} // storeCertificate
	
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
	
	/* *
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {
		return LATEST_VERSION;
	}
	
}
