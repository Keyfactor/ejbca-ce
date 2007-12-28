/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ca.publisher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.dn.DNFieldExtractor;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPModification;

/**
 * LdapPublisher is a class handling a publishing to various v3 LDAP catalouges.  
 *
 * @version $Id: LdapPublisher.java,v 1.33 2007-12-28 10:29:41 nponte Exp $
 */
public class LdapPublisher extends BasePublisher {
	 	
	private static final Logger log = Logger.getLogger(LdapPublisher.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
	protected static byte[] fakecrl = null;
	
	public static final float LATEST_VERSION = 6;
	
	public static final int TYPE_LDAPPUBLISHER = 2;
		
	/** The normal ldap publisher will modify attributes in LDAP.
	 * If you don't want attributes modified, use the LdapSearchPublisher to 
	 * store certificates in already existing entries. Can be overridden in constructor
	 * of subclasses.
	 */
	protected boolean ADD_MODIFICATION_ATTRIBUTES = true;
	
	public static final String DEFAULT_USEROBJECTCLASS     = "top;person;organizationalPerson;inetOrgPerson";
	public static final String DEFAULT_CAOBJECTCLASS       = "top;applicationProcess;certificationAuthority-V2";
	public static final String DEFAULT_CACERTATTRIBUTE     = "cACertificate;binary";
	public static final String DEFAULT_USERCERTATTRIBUTE   = "userCertificate;binary";
	public static final String DEFAULT_CRLATTRIBUTE        = "certificateRevocationList;binary";
	public static final String DEFAULT_DELTACRLATTRIBUTE   = "deltaRevocationList;binary";
	public static final String DEFAULT_ARLATTRIBUTE        = "authorityRevocationList;binary";
	public static final String DEFAULT_PORT                = "389";
	public static final String DEFAULT_SSLPORT             = "636";
	
	
	// Default Values
    
    protected static final String HOSTNAME                 = "hostname";
    protected static final String USESSL                   = "usessl";
    protected static final String PORT                     = "port";
    protected static final String BASEDN                   = "baswdn";
    protected static final String LOGINDN                  = "logindn";
    protected static final String LOGINPASSWORD            = "loginpassword";
    protected static final String CREATENONEXISTING        = "createnonexisting";
    protected static final String MODIFYEXISTING           = "modifyexisting";    
    protected static final String USEROBJECTCLASS          = "userobjectclass";
    protected static final String CAOBJECTCLASS            = "caobjectclass";
    protected static final String USERCERTATTRIBUTE        = "usercertattribute";
    protected static final String CACERTATTRIBUTE          = "cacertattribute";
    protected static final String CRLATTRIBUTE             = "crlattribute";
    protected static final String DELTACRLATTRIBUTE        = "deltacrlattribute";
    protected static final String ARLATTRIBUTE             = "arlattribute";
    protected static final String USEFIELDINLDAPDN         = "usefieldsinldapdn";
    protected static final String ADDMULTIPLECERTIFICATES  = "addmultiplecertificates";
    protected static final String REMOVEREVOKED            = "removerevoked";    
    protected static final String REMOVEUSERONCERTREVOKE   = "removeusersoncertrevoke";    
    protected static final String CREATEINTERMEDIATENODES  = "createintermediatenodes";

    public LdapPublisher(){
    	super();
    	data.put(TYPE, new Integer(TYPE_LDAPPUBLISHER));
    	
        setHostname("");
        setUseSSL(true);
        setPort(DEFAULT_SSLPORT);
        setBaseDN("");
        setLoginDN("");
        setLoginPassword("");
        setCreateNonExisingUsers(true);
        setModifyExistingUsers(true);        
        setUserObjectClass(DEFAULT_USEROBJECTCLASS);
        setCAObjectClass(DEFAULT_CAOBJECTCLASS);
        setUserCertAttribute(DEFAULT_USERCERTATTRIBUTE);
        setCACertAttribute(DEFAULT_CACERTATTRIBUTE);
        setCRLAttribute(DEFAULT_CRLATTRIBUTE);
        setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE);
        setARLAttribute(DEFAULT_ARLATTRIBUTE);     
        setUseFieldInLdapDN(new ArrayList());
        // By default use only one certificate for each user
        setAddMultipleCertificates(false);
        setRemoveRevokedCertificates(true);
        setRemoveUsersWhenCertRevoked(false);
        
        if(fakecrl == null){          
		  try {
			X509CRL crl = CertTools.getCRLfromByteArray(fakecrlbytes);
			fakecrl = crl.getEncoded();
		  } catch (CRLException e) {}
		    catch (IOException e) {}
		}
        
        
    }
    
    // Public Methods


   
    
	/**
	 * Publishes certificate in LDAP, if the certificate is not revoked. If the certifiate is revoked, nothing is done
	 * and the publishing is counted as successful (i.e. returns true).
	 * 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCertificate(Admin admin, Certificate incert, String username, String password, String cafp, int status, int type, long revocationDate, int revocationReason, ExtendedInformation extendedinformation) throws PublisherException{
        log.debug(">storeCertificate(username="+username+")");
        // Don't publish non-active certificates
        if (status != CertificateDataBean.CERT_ACTIVE) {
			String msg = intres.getLocalizedMessage("publisher.notpublrevoked", new Integer(status));
        	log.info(msg);
        	return true;
        }
        int ldapVersion = LDAPConnection.LDAP_V3;
        LDAPConnection lc = createLdapConnection();

        String dn = null;
        String certdn = null;
        try {
            // Extract the users DN from the cert.
        	certdn = CertTools.getSubjectDN((X509Certificate) incert);
            log.debug( "Constructing DN for: " + username);
            dn = constructLDAPDN(certdn);
            log.debug("LDAP DN for user " +username +" is " + dn);
        } catch (Exception e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "certificate");
            log.error(msg, e);            
            throw new PublisherException(msg);            
        }

        // Extract the users email from the cert.
        String email = CertTools.getEMailAddress((X509Certificate)incert);

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = searchOldEntity(username, ldapVersion, lc, dn, email);

        // PART 2: Create LDAP entry
        LDAPEntry newEntry = null;
        ArrayList modSet = new ArrayList();
        LDAPAttributeSet attributeSet = null;
        String attribute = null;
        String objectclass = null;

        if (type == CertificateDataBean.CERTTYPE_ENDENTITY) {
            log.debug("Publishing end user certificate to " + getHostname());

            if (oldEntry != null) {
                // TODO: Are we the correct type objectclass?
                modSet = getModificationSet(oldEntry, certdn, ADD_MODIFICATION_ATTRIBUTES, true);
            } else {
                objectclass = getUserObjectClass(); // just used for logging
                attributeSet = getAttributeSet(incert, getUserObjectClass(), certdn, true, true, password, extendedinformation);
            }

            if (email != null) {
            	//log.debug("Adding email attribute: "+email);
                LDAPAttribute mailAttr = new LDAPAttribute("mail", email);
                if (oldEntry != null) {
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, mailAttr));
                } else {
                    attributeSet.add(mailAttr);
                }
            }

            try {
            	attribute = getUserCertAttribute();
                LDAPAttribute certAttr = new LDAPAttribute(getUserCertAttribute(), incert.getEncoded());
                if (oldEntry != null) {
                	String oldDn = oldEntry.getDN();
                    if (getAddMultipleCertificates()) {
                        modSet.add(new LDAPModification(LDAPModification.ADD, certAttr));                        
                        log.debug("Appended new certificate in user entry; " + username+": "+oldDn);
                    } else {
                        modSet.add(new LDAPModification(LDAPModification.REPLACE, certAttr));                                            
                        log.debug("Replaced certificate in user entry; " + username+": "+oldDn);
                    }
                } else {
                    attributeSet.add(certAttr);
                    log.debug("Added new certificate to user entry; " + username+": "+dn);
                }
            } catch (CertificateEncodingException e) {
    			String msg = intres.getLocalizedMessage("publisher.errorldapencodestore", "certificate");
                log.error(msg, e);
                throw new PublisherException(msg);                
            }
        } else if ((type == CertificateDataBean.CERTTYPE_SUBCA) || (type == CertificateDataBean.CERTTYPE_ROOTCA)) {
            log.debug("Publishing CA certificate to " + getHostname());

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
    			String msg = intres.getLocalizedMessage("publisher.errorldapencodestore", "certificate");
                log.error(msg, e);
                throw new PublisherException(msg);            
            }
        } else {
			String msg = intres.getLocalizedMessage("publisher.notpubltype", new Integer(type));
            log.info(msg);
            throw new PublisherException(msg);                      
        }

        // PART 3: MODIFICATION AND ADDITION OF NEW USERS
        try {
            lc.connect(getHostname(), Integer.parseInt(getPort()));
            // authenticate to the server
            lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));            
            // Add or modify the entry
            if (oldEntry != null && getModifyExistingUsers()) {
                LDAPModification[] mods = new LDAPModification[modSet.size()]; 
                mods = (LDAPModification[])modSet.toArray(mods);
                String oldDn = oldEntry.getDN();
                log.debug("Writing modification to DN: "+oldDn);
                lc.modify(oldDn, mods);
    			String msg = intres.getLocalizedMessage("publisher.ldapmodify", "CERT", oldDn);
                log.info(msg);  
            } else {
            	if(this.getCreateNonExisingUsers()){     
            		if (oldEntry == null) {           
            			// Check if the intermediate parent node is present, and if it is not
            			// we can create it, of allowed to do so by the publisher configuration
            			if(getCreateIntermediateNodes()) {
            				final String parentDN = dn.substring(dn.indexOf(',') + 1);
            				try {
            					lc.read(parentDN);
            				} catch(LDAPException e) {
            					if(e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
            						this.createIntermediateNodes(lc, dn);
                        			String msg = intres.getLocalizedMessage("publisher.ldapaddedintermediate", "CERT", parentDN);
                        			log.info(msg);
            					}
            				}
            			}
            			newEntry = new LDAPEntry(dn, attributeSet);
            			log.debug("Adding DN: "+dn);
            			lc.add(newEntry);
            			String msg = intres.getLocalizedMessage("publisher.ldapadd", "CERT", dn);
            			log.info(msg);
            		}
            	}  
            }
        } catch (LDAPException e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapstore", "certificate", attribute, objectclass, dn);
            log.error(msg, e);  
            throw new PublisherException(msg);            
        } catch (UnsupportedEncodingException e) {
			String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
            log.error(msg, e);
            throw new PublisherException(msg);            
        } finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				String msg = intres.getLocalizedMessage("publisher.errordisconnect", getLoginPassword());
				log.error(msg, e);
			}
		}
        log.debug("<storeCertificate()");
        return true;
		
	}
	
    /**
     * Creates intermediate nodes to host an LDAP entry at <code>dn</code>.
     * @param lc Active LDAP connection
     * @param dn Distinguished name
     * @throws PublisherException
     */
    private void createIntermediateNodes(LDAPConnection lc, String dn) throws PublisherException {
        LDAPAttributeSet attrSet;
        LDAPEntry entry;
        String dnFragment, rdn, field, value;
        int ix = dn.lastIndexOf(getBaseDN()) - 1;

        while((ix = dn.lastIndexOf(',', ix - 1)) >= 0) {
            dnFragment = dn.substring(ix + 1);
            rdn = dnFragment.substring(0, dnFragment.indexOf(','));
            field = rdn.substring(0, rdn.indexOf('='));
            value = rdn.substring(rdn.indexOf('=') + 1);
            try {
                lc.read(dnFragment);
            } catch(LDAPException e) {
                if(e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                    attrSet = new LDAPAttributeSet();
                    attrSet.add(getObjectClassAttribute(field));
                    attrSet.add(new LDAPAttribute(field.toLowerCase(), value));
                    entry = new LDAPEntry(dnFragment, attrSet);

                    try {
                        lc.add(entry);
                        log.debug("Created node " + dnFragment);
                    } catch(LDAPException e1) {
            			String msg = intres.getLocalizedMessage("publisher.ldapaddedintermediate", dnFragment);
            			log.error(msg, e1);
                        throw new PublisherException(msg);            
                    }
                }
            }
        }
    }

    /**
     * Returns an LDAPAttribute initialized with the LDAP object class
     * definition that corresponds to a DN <code>field</code>.
     * <p>The only allowed fields are </code>O</code> (organization) and
     * <code>OU</code> (organizationalUnit).</p>
     *
     * @param field A DN field (case-insensitive). Only <code>O</code> and
     * <code>OU</code> are allowed. 
     * @return LDAPAttribute initialized with the LDAP object class definition
     * that corresponds to a DN <code>field</code>.
     */
    private LDAPAttribute getObjectClassAttribute(String field) {
        final String lowCaseField = field.toLowerCase();
        if(lowCaseField.equals("o")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "organization" });
        } else if(lowCaseField.equals("ou")) {
            return new LDAPAttribute("objectclass", new String[] { "top", "organizationalUnit" });
        } else {
			String msg = intres.getLocalizedMessage("publisher.ldapintermediatenotappropriate", field);
			log.warn(msg);
            return new LDAPAttribute("objectclass");
        }
    }
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) throws PublisherException{
        int ldapVersion = LDAPConnection.LDAP_V3;
        LDAPConnection lc = createLdapConnection();

        X509CRL crl = null;
        String dn = null;
        String crldn = null;
        try {
            // Extract the users DN from the crl.
            crl = CertTools.getCRLfromByteArray(incrl);
        	crldn = CertTools.getIssuerDN(crl);
            dn = constructLDAPDN(CertTools.getIssuerDN(crl));
        } catch (Exception e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "CRL");
        	log.error(msg, e);        	
        	throw new PublisherException(msg);            
        }

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = searchOldEntity(null, ldapVersion, lc, dn, null);

        LDAPEntry newEntry = null;
        ArrayList modSet = new ArrayList();
        LDAPAttributeSet attributeSet = null;

        if (oldEntry != null) {
            modSet = getModificationSet(oldEntry, crldn, false, false);
        } else {
            attributeSet = getAttributeSet(null, this.getCAObjectClass(), crldn, true, false, null,null);
        }

        try {
        	if(crl.getExtensionValue(X509Extensions.DeltaCRLIndicator.getId()) != null) {
        		// It's a delta CRL.
        		LDAPAttribute attr = new LDAPAttribute(getDeltaCRLAttribute(), crl.getEncoded());
        		if (oldEntry != null) {
        			modSet.add(LDAPModification.REPLACE, attr);
        		} else {
        			attributeSet.add(attr);
        		}
        	} else {
        		// It's a CRL
        		LDAPAttribute crlAttr = new LDAPAttribute(getCRLAttribute(), crl.getEncoded());
        		LDAPAttribute arlAttr = new LDAPAttribute(getARLAttribute(), crl.getEncoded());
        		if (oldEntry != null) {
        			modSet.add(new LDAPModification(LDAPModification.REPLACE, crlAttr));
        			modSet.add(new LDAPModification(LDAPModification.REPLACE, arlAttr));
        		} else {
        			attributeSet.add(crlAttr);
        			attributeSet.add(arlAttr);
        		}
        	}
        } catch (CRLException e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapencodestore", "CRL");
            log.error(msg, e);
            throw new PublisherException(msg);            
        }
        if (oldEntry == null) {
            newEntry = new LDAPEntry(dn, attributeSet);
        }
        try {
            // connect to the server
            lc.connect(getHostname(), Integer.parseInt(getPort()));
            // authenticate to the server
            lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
            // Add or modify the entry
            if (oldEntry != null) {
                LDAPModification[] mods = new LDAPModification[modSet.size()]; 
                mods = (LDAPModification[])modSet.toArray(mods);
                lc.modify(dn, mods);
    			String msg = intres.getLocalizedMessage("publisher.ldapmodify", "CRL", dn);
                log.info(msg);  
            } else {
                lc.add(newEntry);
    			String msg = intres.getLocalizedMessage("publisher.ldapadd", "CRL", dn);
                log.info(msg);  
            }
        } catch (LDAPException e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapstore", "CRL", getCRLAttribute(), getCAObjectClass(), dn);
            log.error(msg, e);
            throw new PublisherException(msg);                        
        } catch (UnsupportedEncodingException e) {
			String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
            log.error(msg, e);
            throw new PublisherException(msg);            
        } finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				String msg = intres.getLocalizedMessage("publisher.errordisconnect");
				log.error(msg, e);
			}
		}
        return true;
    }
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public void revokeCertificate(Admin admin, Certificate cert, String username, int reason) throws PublisherException{
        log.debug(">revokeCertificate()");
        // Check first if we should do anything then revoking
        boolean removecert = getRemoveRevokedCertificates();
        boolean removeuser = getRemoveUsersWhenCertRevoked();
        if ( (!removecert) && (!removeuser) ) {
            log.debug("The configuration for the publisher '" + getDescription() + "' does not allow removing of certificates or users.");
            return;
        }
        if (removecert) log.debug("Removing user certificate from ldap");
        if (removeuser) log.debug("Removing user entry from ldap");

        int ldapVersion = LDAPConnection.LDAP_V3;
        LDAPConnection lc = createLdapConnection();

        String dn = null;
        String certdn = null;
        try {
            // Extract the users DN from the cert.
        	certdn = CertTools.getSubjectDN((X509Certificate) cert);
            dn = constructLDAPDN(certdn);
        } catch (Exception e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "certificate");
            log.error(msg, e);            
            throw new PublisherException(msg);            
        }

        // Extract the users email from the cert.
        String email = CertTools.getEMailAddress((X509Certificate)cert);

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = searchOldEntity(username, ldapVersion, lc, dn, email);
        
        ArrayList modSet = new ArrayList();
                                
        if (((X509Certificate) cert).getBasicConstraints() == -1) {
            log.debug("Removing end user certificate from " + getHostname());

            if (oldEntry != null) {          
            	if (removecert) {
                    // Don't try to remove the cert if there does not exist any
                    LDAPAttribute oldAttr = oldEntry.getAttribute(getUserCertAttribute());
                    if (oldAttr != null) {
                        modSet = getModificationSet(oldEntry, certdn, false, true);
                        LDAPAttribute attr = new LDAPAttribute(getUserCertAttribute());
                        modSet.add(new LDAPModification(LDAPModification.DELETE, attr));                    
                    } else {
            			String msg = intres.getLocalizedMessage("publisher.inforevokenocert");
                        log.info(msg);
                    }            		
            	}
            } else {
    			String msg = intres.getLocalizedMessage("publisher.errorrevokenoentry");
                log.error(msg);            
                throw new PublisherException(msg);            
            }
        } else  {
            log.debug("Not removing CA certificate from " + getHostname() + "Because of object class restrictions.");
            // Currently removal of CA certificate isn't support because of object class restictions
            /*
            if (oldEntry != null) {
                modSet = getModificationSet(oldEntry, dn, false, false);
                modSet.add(new LDAPModification(LDAPModification.DELETE, new LDAPAttribute(getCACertAttribute())));
            } else {
                log.error("Certificate doesn't exist in database");            
                throw new PublisherException("Certificate doesn't exist in database");            
            }*/
        }

        try {
        
            lc.connect(getHostname(), Integer.parseInt(getPort()));
            // authenticate to the server
            lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));            
            // Add or modify the entry
            if (oldEntry != null && modSet != null && getModifyExistingUsers()) {
            	if (removecert) {
                    LDAPModification[] mods = new LDAPModification[modSet.size()]; 
                    mods = (LDAPModification[])modSet.toArray(mods);
                    lc.modify(oldEntry.getDN(), mods);            		
            	}
            	if (removeuser) {
                    lc.delete(oldEntry.getDN());            		
            	}
    			String msg = intres.getLocalizedMessage("publisher.ldapremove", dn);
                log.info(msg);  
            }               
        } catch (LDAPException e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapremove", dn);
            log.error(msg, e);  
            throw new PublisherException(msg);            
        } catch (UnsupportedEncodingException e) {
			String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
            log.error(msg, e);
            throw new PublisherException(msg);            
        } finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				String msg = intres.getLocalizedMessage("publisher.errordisconnect");
				log.error(msg, e);
			}
		}
        log.debug("<revokeCertificate()");
	}

    /** SearchOldEntity is the only method differing between regular ldap and ldap search publishers.
     *  Aprat from how they find existing users, the publishing works the same.
     */
    protected LDAPEntry searchOldEntity(String username, int ldapVersion, LDAPConnection lc, String dn, String email) throws PublisherException {
        LDAPEntry oldEntry = null; // return value
        try {
            // connect to the server
            lc.connect(getHostname(), Integer.parseInt(getPort()));
            // authenticate to the server
            lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
            // try to read the old object
            oldEntry = lc.read(dn);
        } catch (LDAPException e) {
            if (e.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                log.debug("No old entry exist for '" + dn + "'.");
            } else {
    			String msg = intres.getLocalizedMessage("publisher.errorldapbind", e.getMessage());
                log.error(msg, e);
                throw new PublisherException(msg);                                
            }
        } catch (UnsupportedEncodingException e) {
			String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
            throw new PublisherException(msg);            
        } finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				String msg = intres.getLocalizedMessage("publisher.errordisconnect");
				log.error(msg, e);
			}
		}
        return oldEntry;
    }
    
	/**
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher
	 */    
	public void testConnection(Admin admin) throws PublisherConnectionException {
		int ldapVersion = LDAPConnection.LDAP_V3;
		LDAPConnection lc = null;
		if(getUseSSL()){
			lc = new LDAPConnection(new LDAPJSSESecureSocketFactory());
		}else{
			lc = new LDAPConnection();        
		}
		
		LDAPEntry entry = null;
		try {
			// connect to the server
			lc.connect(getHostname(), Integer.parseInt(getPort()));
			// authenticate to the server
			lc.bind(ldapVersion, getLoginDN(), getLoginPassword().getBytes("UTF8"));
			// try to read the old object
			entry = lc.read(getBaseDN());			
			log.debug("Entry" + entry.toString());
			if(entry == null) {
    			String msg = intres.getLocalizedMessage("publisher.errornobinddn");
				throw new PublisherConnectionException(msg);
			}
		} catch (LDAPException e) {
			String msg = intres.getLocalizedMessage("publisher.errorldapbind", e.getMessage());
			log.error(msg, e);
			throw new PublisherConnectionException(msg);                            
        } catch (UnsupportedEncodingException e) {
			String msg = intres.getLocalizedMessage("publisher.errorpassword", getLoginPassword());
            log.error(msg, e);
            throw new PublisherConnectionException(msg);            
		} finally {
			// disconnect with the server
			try {
				lc.disconnect();
			} catch (LDAPException e) {
				String msg = intres.getLocalizedMessage("publisher.errordisconnect");
				log.error(msg, e);
			}
		}
	} 

    protected LDAPConnection createLdapConnection() {
        LDAPConnection lc;
        if (getUseSSL()) {
            lc = new LDAPConnection(new LDAPJSSESecureSocketFactory());
        } else {
            lc = new LDAPConnection();
        }
        return lc;
    }

    /**
     *  Returns the hostname of ldap server.
     */    
    public String getHostname (){
    	return (String) data.get(HOSTNAME);
    }

    /**
     *  Sets the hostname of ldap server.
     */        
    public void setHostname (String hostname){
    	data.put(HOSTNAME, hostname);	
    }
    
    /**
     *  Returns true if SSL connetion should be used.
     */    
    public boolean getUseSSL (){
    	return ((Boolean) data.get(USESSL)).booleanValue();
    }

    /**
     *  Sets if SSL connetion should be used.
     */        
    public void setUseSSL (boolean usessl){
    	data.put(USESSL, Boolean.valueOf(usessl));	
    }
    
    /**
     *  Returns the port of ldap server.
     */    
    public String getPort (){
    	return (String) data.get(PORT);
    }

    /**
     *  Sets the port of ldap server.
     */        
    public void setPort(String port){
    	data.put(PORT, port);	
    }
	
    /**
     *  Returns the basedn of ldap server.
     */    
    public String getBaseDN(){
    	return (String) data.get(BASEDN);
    }

    /**
     *  Sets the basedn of ldap server.
     */        
    public void setBaseDN(String basedn){
    	data.put(BASEDN, basedn);	
    }

    /**
     *  Returns the logindn to the ldap server.
     */    
    public String getLoginDN(){
    	return (String) data.get(LOGINDN);
    }

    /**
     *  Sets the logindn to the ldap server.
     */        
    public void setLoginDN(String logindn){
    	data.put(LOGINDN, logindn);	
    }

    /**
     *  Returns the loginpwd to the ldap server.
     */    
    public String getLoginPassword(){
    	return (String) data.get(LOGINPASSWORD);
    }

    /**
     *  Sets the loginpwd to the ldap server.
     */        
    public void setLoginPassword(String loginpwd){
    	data.put(LOGINPASSWORD, loginpwd);	
    }

    /**
     *  Returns true if nonexisting users should be created
     */    
    public boolean getCreateNonExisingUsers (){
    	return ((Boolean) data.get(CREATENONEXISTING)).booleanValue();
    }

    /**
     *  Sets if nonexisting users should be created.
     */        
    public void setCreateNonExisingUsers (boolean createnonexistingusers){
    	data.put(CREATENONEXISTING, Boolean.valueOf(createnonexistingusers));	
    }
	
    /**
     *  Returns true if existing users should be modified.
     */    
    public boolean getModifyExistingUsers (){
    	return ((Boolean) data.get(MODIFYEXISTING)).booleanValue();
    }

    /**
     *  Sets if existing users should be modified.
     */        
    public void setModifyExistingUsers (boolean modifyexistingusers){
    	data.put(MODIFYEXISTING, Boolean.valueOf(modifyexistingusers));	
    }

    /**
     *  Returns the user object class in the ldap instance
     */    
    public String getUserObjectClass(){
    	return (String) data.get(USEROBJECTCLASS);
    }

    /**
     *  Sets the user object class in the ldap instance
     */        
    public void setUserObjectClass(String userobjectclass){
    	data.put(USEROBJECTCLASS, userobjectclass);	
    }

    /**
     *  Returns the CA object class in the ldap instance
     */    
    public String getCAObjectClass(){
    	return (String) data.get(CAOBJECTCLASS);
    }

    /**
     *  Sets the CA object class in the ldap instance
     */        
    public void setCAObjectClass(String caobjectclass){
    	data.put(CAOBJECTCLASS, caobjectclass);	
    }

    /**
     *  Returns the user cert attribute in the ldap instance
     */    
    public String getUserCertAttribute(){
    	return (String) data.get(USERCERTATTRIBUTE);
    }

    /**
     *  Sets the user cert attribute in the ldap instance
     */        
    public void setUserCertAttribute(String usercertattribute){
    	data.put(USERCERTATTRIBUTE, usercertattribute);	
    }

    /**
     *  Returns the ca cert attribute in the ldap instance
     */    
    public String getCACertAttribute(){
    	return (String) data.get(CACERTATTRIBUTE);
    }

    /**
     *  Sets the ca cert attribute in the ldap instance
     */        
    public void setCACertAttribute(String cacertattribute){
    	data.put(CACERTATTRIBUTE, cacertattribute);	
    }

    /**
     *  Returns the CRL attribute in the ldap instance
     */    
    public String getCRLAttribute(){
    	return (String) data.get(CRLATTRIBUTE);
    }

    /**
     *  Sets the CRL attribute in the ldap instance
     */        
    public void setCRLAttribute(String crlattribute){
    	data.put(CRLATTRIBUTE, crlattribute);	
    }

    /**  Returns the delta CRL attribute in the ldap instance
     */
    public String getDeltaCRLAttribute(){
    	if(data.get(DELTACRLATTRIBUTE) == null) {
    		this.setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE);
    		return DEFAULT_DELTACRLATTRIBUTE;
    	} else {
    		return (String) data.get(DELTACRLATTRIBUTE);
    	}
    }

    /**
     *  Sets the delta CRL attribute in the ldap instance
     */
    public void setDeltaCRLAttribute(String deltacrlattribute){
    	data.put(DELTACRLATTRIBUTE, deltacrlattribute);   
    }

    /**
     *  Returns the ARL attribute in the ldap instance
     */    
    public String getARLAttribute(){
    	return (String) data.get(ARLATTRIBUTE);
    }

    /**
     *  Sets the ARL attribute in the ldap instance
     */        
    public void setARLAttribute(String arlattribute){
    	data.put(ARLATTRIBUTE, arlattribute);	
    }
    
    /**
     * Method getting a collection of DNFieldExtractor constants indicating which
     * fields of the x509 certificate DN that should be used in the LDAP DN.
     * 
     * Valid values are  DNFieldExtractor.E, .UID, .CN, .SN, .GIVENNAME, .SURNAME, .T, .OU, .L 
     * Other values should be defined in baseDN instead.
     * If there exists multiple fields of the same type, then will all fields be mappen to LDAP dn.
     * 
     * @return Collection of (Integer) containing DNFieldExtractor constants.
     */
    public Collection getUseFieldInLdapDN(){
    	return (Collection) data.get(USEFIELDINLDAPDN);
    }

    /**
     * Method setting a collection of DNFieldExtractor constants indicating which
     * fields of the x509 certificate DN that should be used in the LDAP DN.
     * 
     * Valid values are  DNFieldExtractor.E, .UID, .CN, .SN, .GIVENNAME, .SURNAME, .T, .OU, .L 
     * Other values should be defined in baseDN instead.
     * If there exists multiple fields of the same type, then will all fields be mappen to LDAP dn.
     * 
     * @return Collection of (Integer) containing DNFieldExtractor constants.
     */
    
    public void setUseFieldInLdapDN(Collection usefieldinldapdn){
    	data.put(USEFIELDINLDAPDN, usefieldinldapdn);
    }    

    /**
     *  Returns true if multiple certificates should be appended to existing user entries, instead of replacing.
     */    
    public boolean getAddMultipleCertificates (){
        return ((Boolean) data.get(ADDMULTIPLECERTIFICATES)).booleanValue();
    }
    /**
     *  Sets if multiple certificates should be appended to existing user entries, instead of replacing.
     */        
    public void setAddMultipleCertificates (boolean appendcerts){
        data.put(ADDMULTIPLECERTIFICATES, Boolean.valueOf(appendcerts)); 
    }

    public void setRemoveRevokedCertificates( boolean removerevoked ){
        data.put(REMOVEREVOKED, Boolean.valueOf(removerevoked));  
    }
    
    public boolean getRemoveRevokedCertificates(){
        boolean removerevoked = true; //-- default value
        if ( data.get(REMOVEREVOKED) != null ) {
            removerevoked = ((Boolean)data.get(REMOVEREVOKED)).booleanValue();
        }
        return removerevoked;
    }
    
    public void setRemoveUsersWhenCertRevoked( boolean removeuser ){
        data.put(REMOVEUSERONCERTREVOKE, Boolean.valueOf(removeuser));  
    }
    
    public boolean getRemoveUsersWhenCertRevoked(){
        boolean removeuser = false; //-- default value
        if ( data.get(REMOVEUSERONCERTREVOKE) != null ) {
        	removeuser = ((Boolean)data.get(REMOVEUSERONCERTREVOKE)).booleanValue();
        }
        return removeuser;
    }

    public void setCreateIntermediateNodes( boolean createnodes ){
        data.put(CREATEINTERMEDIATENODES, Boolean.valueOf(createnodes));  
    }
    
    public boolean getCreateIntermediateNodes(){
        boolean createnodes = false; //-- default value
        if ( data.get(CREATEINTERMEDIATENODES) != null ) {
            createnodes = ((Boolean)data.get(CREATEINTERMEDIATENODES)).booleanValue();
        }
        return createnodes;
    }

    // Private methods
    /**
     * Creates an LDAPAttributeSet.
     *
     * @param cert the certificate to use or null if no cert involved.
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @param person true if this is a person-entry, false if it is a CA.
     * @param password, currently only used for the AD publisher
     * @param extendedinformation, for future use...
     *
     * @return LDAPAtributeSet created...
     */
    protected LDAPAttributeSet getAttributeSet(Certificate cert, String objectclass, String dn, boolean extra, boolean person,
    		                                   String password, ExtendedInformation extendedinformation) {
    	log.debug(">getAttributeSet()");
        LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        LDAPAttribute attr = new LDAPAttribute("objectclass");
        // The full LDAP object tree is divided with ; in the objectclass
        StringTokenizer token = new StringTokenizer(objectclass,";");
        while (token.hasMoreTokens()) {
            String value = token.nextToken();
            log.debug("Adding objectclass value: "+value);
            attr.addValue(value);
        }
        attributeSet.add(attr);

        /* To Add an entry to the directory,
         *   -- Create the attributes of the entry and add them to an attribute set
         *   -- Specify the DN of the entry to be created
         *   -- Create an LDAPEntry object with the DN and the attribute set
         *   -- Call the LDAPConnection add method to add it to the directory
         */
        if (extra) {
        	String cn = CertTools.getPartFromDN(dn, "CN");
        	if (cn != null) {
        		attributeSet.add(new LDAPAttribute("cn", cn));
        	}
        	String l = CertTools.getPartFromDN(dn, "L");
        	if (l != null) {
        		attributeSet.add(new LDAPAttribute("l", l));
        	}
        	String ou = CertTools.getPartFromDN(dn, "OU");
        	if (ou != null) {
        		attributeSet.add(new LDAPAttribute("ou", ou));
        	}
        	// Only persons have (normally) all these extra attributes. 
        	// A CA might have them if you don't use the default objectClass, but we don't
        	// handle that case.
        	if (person) {
        		// sn means surname in LDAP, and is required for persons
        		String sn = CertTools.getPartFromDN(dn, "SURNAME");
        		if ( (sn == null) && (cn != null) ) {
        		    // Only construct this if we are the standard object class
        		    if (getUserObjectClass().endsWith("inetOrgPerson")) {
        		        // Take surname to be the last part of the cn
        		        int index = cn.lastIndexOf(' ');
        		        if (index <=0) {
        		            // If there is no natural sn, use cn since sn is required
        		            sn = cn;
        		        } else {
        		            if (index < cn.length()) sn = cn.substring(index+1);
        		        }
        		    }
        		}
        		if (sn != null) {
        			attributeSet.add(new LDAPAttribute("sn", sn));
        		}
        		// gn means givenname in LDAP, and is required for persons
        		String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
        		if ( (gn == null) && (cn != null) ) {
        		    // Only construct this if we are the standard object class
        		    if (getUserObjectClass().endsWith("inetOrgPerson")) {
        		        // Take givenname to be the first part of the cn
        		        int index = cn.indexOf(' ');
        		        if (index <=0) {
        		            // If there is no natural gn/sn, ignore gn if we are using sn
        		            if (sn == null) gn = cn;
        		        } else {
        		            gn = cn.substring(0, index);
        		        }
        		    }
        		}
        		if (gn != null) {
        			attributeSet.add(new LDAPAttribute("givenName", gn));
        		}
        		String st = CertTools.getPartFromDN(dn, "ST");
        		if (st != null) {
        			attributeSet.add(new LDAPAttribute("st", st));
        		}
        		String o = CertTools.getPartFromDN(dn, "O");
        		if (o != null) {
        			attributeSet.add(new LDAPAttribute("o", o));
        		}
        		String uid = CertTools.getPartFromDN(dn, "uid");
        		if (uid != null) {
        			attributeSet.add(new LDAPAttribute("uid", uid));
        		}        
        		String initials = CertTools.getPartFromDN(dn, "initials");
        		if (initials != null) {
        			attributeSet.add(new LDAPAttribute("initials", initials));
        		}        
        		String title = CertTools.getPartFromDN(dn, "T");
        		if (title != null) {
        			attributeSet.add(new LDAPAttribute("title", title));
        		}
        		// If we have selected to use the SN (serialNUmber DN field, we will also add it as an attribute
        		// This is not present in the normal objectClass (inetOrgPerson)
        		// Modifying the schema is as simple as adding serialNumber as MAY in the inetOrgPerson object class in inetorgperson.schema.
            	Collection usefields = getUseFieldInLdapDN();
            	if (usefields.contains(new Integer(DNFieldExtractor.SN))) {
            		String serno = CertTools.getPartFromDN(dn, "SN");
            		if (serno != null) {
            			attributeSet.add(new LDAPAttribute("serialNumber", serno));
            		}            		
            	}
        	}
        }
    	log.debug("<getAttributeSet()");
        return attributeSet;
    } // getAttributeSet
	
	
    /**
     * Creates an LDAPModificationSet.
     *
     * @param oldEntry the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the
     *        modificationset.
     * @param pserson true if this is a person-entry, false if it is a CA.
     *
     * @return LDAPModificationSet created...
     */
    protected ArrayList getModificationSet(LDAPEntry oldEntry, String dn, boolean extra, boolean person) {
    	log.debug(">getModificationSet()");
        ArrayList modSet = new ArrayList();

        // We get this, because we can not modify attributes that are present in the original DN
        // i.e. if the ldap entry have a DN, we are not allowed to modify that
        String oldDn = oldEntry.getDN();
        
        if (extra) {
        	log.debug("Adding extra attributes to modificationSet");
        	String cn = CertTools.getPartFromDN(dn, "CN");
        	String oldcn = CertTools.getPartFromDN(oldDn, "CN");
        	if ( (cn != null) && (oldcn == null) ) {
                LDAPAttribute attr = new LDAPAttribute("cn", cn);
        		modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        	}
            String l = CertTools.getPartFromDN(dn, "L");
        	String oldl = CertTools.getPartFromDN(oldDn, "L");
            if ( (l != null) && (oldl == null) ) {
                LDAPAttribute attr = new LDAPAttribute("l", l);
                modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
            }
            String ou = CertTools.getPartFromDN(dn, "OU");
        	String oldou = CertTools.getPartFromDN(oldDn, "OU");
            if ( (ou != null) && (oldou == null) ) {
                LDAPAttribute attr = new LDAPAttribute("ou", ou);
                modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
            }
        	// Only persons have (normally) all these extra attributes. 
        	// A CA might have them if you don't use the default objectClass, but we don't
        	// handle that case.
        	if (person) {
        		// sn means surname in LDAP, and is required for inetOrgPerson
        		String sn = CertTools.getPartFromDN(dn, "SURNAME");
        		if ( (sn == null) && (cn != null) ) {
                    // Only construct this if we are the standard object class
                    if (getUserObjectClass().endsWith("inetOrgPerson")) {
                        // Take surname to be the last part of the cn
                        int index = cn.lastIndexOf(' ');
                        if (index <=0) {
                            // If there is no natural sn, use cn since sn is required
                            sn = cn;
                        } else {
                            if (index < cn.length()) sn = cn.substring(index+1);
                        }                        
                    }
        		}
        		if (sn != null) {
                    LDAPAttribute attr = new LDAPAttribute("sn", sn);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		// gn means givenname in LDAP, and is required for inetOrgPerson
        		String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
        		if ( (gn == null) && (cn != null) ) {
        		    // Only construct this if we are the standard object class
        		    if (getUserObjectClass().endsWith("inetOrgPerson")) {
        		        // Take givenname to be the first part of the cn
        		        int index = cn.indexOf(' ');
        		        if (index <=0) {
        		            // If there is no natural gn/sn, ignore gn if we are using sn
        		            if (sn == null) gn = cn;
        		        } else {
        		            gn = cn.substring(0, index);
        		        }
        		    }
        		}
        		if (gn != null) {
                    LDAPAttribute attr = new LDAPAttribute("givenName", gn);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		String st = CertTools.getPartFromDN(dn, "ST");
            	String oldst = CertTools.getPartFromDN(oldDn, "ST");
        		if ( (st != null) && (oldst == null) ){
                    LDAPAttribute attr = new LDAPAttribute("st", st);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		String o = CertTools.getPartFromDN(dn, "O");
            	String oldo = CertTools.getPartFromDN(oldDn, "O");
        		if ( (o != null) && (oldo == null) ) {
                    LDAPAttribute attr = new LDAPAttribute("o", o);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		String uid = CertTools.getPartFromDN(dn, "uid");
            	String olduid = CertTools.getPartFromDN(oldDn, "uid");
        		if ( (uid != null) && (olduid == null) ) {
                    LDAPAttribute attr = new LDAPAttribute("uid", uid);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		String initials = CertTools.getPartFromDN(dn, "initials");
        		if (initials != null) {
                    LDAPAttribute attr = new LDAPAttribute("initials", initials);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}        
        		String title = CertTools.getPartFromDN(dn, "T");
        		if (title != null) {
                    LDAPAttribute attr = new LDAPAttribute("title", title);
                    modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
        		}
        		// If we have selected to use the SN (serialNUmber DN field, we will also add it as an attribute
        		// This is not present in the normal objectClass (inetOrgPerson)
            	Collection usefields = getUseFieldInLdapDN();
            	if (usefields.contains(new Integer(DNFieldExtractor.SN))) {
            		String serno = CertTools.getPartFromDN(dn, "SN");
                	String oldserno = CertTools.getPartFromDN(oldDn, "SN");
            		if ( (serno != null) && (oldserno == null) ) {
                        LDAPAttribute attr = new LDAPAttribute("serialNumber", serno);
                        modSet.add(new LDAPModification(LDAPModification.REPLACE, attr));
            		}            		
            	}
        	}
        }
    	log.debug("<getModificationSet()");
        return modSet;
    } // getModificationSet
    
    protected String constructLDAPDN(String dn){
    	String retval = "";
    	DNFieldExtractor extractor = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTDN); 
    	
    	Collection usefields = getUseFieldInLdapDN();
    	if(usefields instanceof List){
    		Collections.sort((List) usefields);
    	}
    	Iterator iter = usefields.iterator(); 
    	String dnField = null;
    	while(iter.hasNext()){
    		Integer next = (Integer) iter.next();
    		dnField = extractor.getFieldString(next.intValue());
    		if (StringUtils.isNotEmpty(dnField)) {
                if (dnField.startsWith("SN")) {
                    // This is SN in Bouncycastle, but it should be serialNumber in LDAP
                    dnField = "serialNumber"+dnField.substring(2);
                }
                if (dnField.startsWith("E")) {
                    // This is E in Bouncycastle, but it should be mail in LDAP
                    dnField = "mail"+dnField.substring(1);
                }
    			if(retval.length() == 0) {
    				retval += dnField; // first item, don't start with a comma
    			} else {
    				retval += "," + dnField;
    			}
    		}
    	}
    	retval = retval + "," + this.getBaseDN();
    	log.debug("LdapPublisher: constructed DN: " + retval );
    	return retval;	
    }
    
    protected static byte[] fakecrlbytes = Base64.decode(
    ("MIIBKDCBkgIBATANBgkqhkiG9w0BAQUFADAvMQ8wDQYDVQQDEwZUZXN0Q0ExDzAN"+
    "BgNVBAoTBkFuYVRvbTELMAkGA1UEBhMCU0UXDTA0MDExMjE0MTQyMloXDTA0MDEx"+
    "MzE0MTQyMlqgLzAtMB8GA1UdIwQYMBaAFK1tyidIzx1qpuj5OjHl/0Ro8xTDMAoG"+
    "A1UdFAQDAgEBMA0GCSqGSIb3DQEBBQUAA4GBABBSCWRAX8xyWQSuZYqR9MC8t4/V"+
    "Tp4xTGJeT1OPlCfuyeHyjUdvdjB/TjTgc4EOJ7eIF7aQU8Mp6AcUAKil/qBlrTYa"+
    "EFVr0WDeh2Aglgm4klAFnoJjDWfjTP1NVFdN4GMizqAz/vdXOY3DaDmkwx24eaRw"+
    "7SzqXca4gE7f1GTO").getBytes());
	
	
		
	/** 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		LdapPublisher clone = new LdapPublisher();
		HashMap clonedata = (HashMap) clone.saveData();

		Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
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
	
    /** 
     * Implemtation of UpgradableDataHashMap function upgrade. 
     */
    public void upgrade() {
        log.debug(">upgrade");
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
			String msg = intres.getLocalizedMessage("publisher.upgrade", new Float(getVersion()));
            log.info(msg);
            if(data.get(ADDMULTIPLECERTIFICATES) == null) {
                setAddMultipleCertificates(false);                
            }
            if(data.get(REMOVEREVOKED) == null) {
                setRemoveRevokedCertificates(true);                
            }
            if(data.get(REMOVEUSERONCERTREVOKE) == null) {
                setRemoveUsersWhenCertRevoked(false);                
            }
            if(data.get(CREATEINTERMEDIATENODES) == null) {
            	setCreateIntermediateNodes(false); // v6
            }

            if(data.get(DELTACRLATTRIBUTE) == null) {
            	setDeltaCRLAttribute(DEFAULT_DELTACRLATTRIBUTE); // v7
            }

            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.debug("<upgrade");
    }

}
