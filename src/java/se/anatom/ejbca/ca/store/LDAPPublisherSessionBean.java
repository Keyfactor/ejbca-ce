package se.anatom.ejbca.ca.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPModificationSet;


/**
 * Stores certificates and CRL in an LDAP v3 directory.
 * 
 * <p>
 * LDAP schema required:<br>
 * Certificates for CERTTYPE_ENDENTITY are published as attribute 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * Certificates for CERTTYPE_CA and CERTTYPE_ROOTCA are published as attribute cACertificate in
 * objectclass 'certificationAuthority'.<br>
 * CRLs are published as attribute 'certificateRevocationList' in objectclass
 * 'certificationAuthority'.
 * </p>
 * 
 * <p>
 * In 'inetOrgPerson' the following attributes are set if present in the certificate:
 * <pre>
 * DN
 * cn
 * ou
 * l
 * st
 * sn
 * mail
 * userCertificate
 * </pre>
 * </p>
 * 
 * <p>
 * In 'certificationAuthority' the only attributes set are:
 * <pre>
 * DN
 * cACertificate
 * </pre>
 * </p>
 *
 * @version $Id: LDAPPublisherSessionBean.java,v 1.26 2004-01-26 12:49:08 anatom Exp $
 */
public class LDAPPublisherSessionBean extends BaseSessionBean {
    private String ldapHost = "localhost";
    private int ldapPort = LDAPConnection.DEFAULT_PORT;
    private String loginDN = "cn=Admin,o=AnaTom,c=SE";
    private String loginPassword = "foo123";
    private String containerName = "o=AnaTom,c=SE";
    private String userObjectclass = "inetOrgPerson";
    private String cAObjectclass = "certificateAuthority";
    private String cRLAttribute = "certificateRevocationList;binary";
    private String aRLAttribute = "authorityRevocationList;binary";
    private String userCertAttribute = "userCertificate;binary";
    private String cACertAttribute = "cACertificate;binary";

    /** The remote interface of the log session bean */
    private ILogSessionLocal logsession;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        ldapHost = (String) lookup("java:comp/env/ldapHost", java.lang.String.class);
        ldapPort = ((Integer) lookup("java:comp/env/ldapPort", java.lang.Integer.class)).intValue();
        loginDN = (String) lookup("java:comp/env/loginDN", java.lang.String.class);
        loginPassword = (String) lookup("java:comp/env/loginPassword", java.lang.String.class);
        containerName = (String) lookup("java:comp/env/containerName", java.lang.String.class);
        userObjectclass = (String) lookup("java:comp/env/userObjectclass", java.lang.String.class);
        cAObjectclass = (String) lookup("java:comp/env/cAObjectclass", java.lang.String.class);
        cRLAttribute = (String) lookup("java:comp/env/cRLAttribute", java.lang.String.class);
        aRLAttribute = (String) lookup("java:comp/env/aRLAttribute", java.lang.String.class);
        userCertAttribute = (String) lookup("java:comp/env/userCertAttribute", java.lang.String.class);
        cACertAttribute = (String) lookup("java:comp/env/cACertAttribute", java.lang.String.class);
        debug("ldapHost=" + ldapHost);
        debug("loginDN=" + loginDN);
        debug("loginPassword=" + loginPassword);
        debug("containerName=" + containerName);
        debug("userObjectclass=" + userObjectclass);
        debug("cAObjectclass=" + cAObjectclass);
        debug("<ejbCreate()");

        try {
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",
                    ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Publishes a certificate to LDAP. Creates entry if it does not exist.
     *
     * @param admin Fingerprint (hex) of the CAs certificate.
     * @param incert The certificate to be stored.
     * @param username username of end entity owning the certificate.
     * @param cafp fingerprint of CA certificate, issuer of this cert
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type) {
        debug(">storeCertificate(username="+username+")");
        int ldapVersion = LDAPConnection.LDAP_V3;
        LDAPConnection lc = new LDAPConnection();

        String dn = null;

        try {
            // Extract the users DN from the cert.
            dn = CertTools.getSubjectDN((X509Certificate) incert);
        } catch (Exception e) {
            error("Error decoding input certificate: ", e);            
             logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert,
                    LogEntry.EVENT_ERROR_STORECERTIFICATE, "Error decoding input certificate.");
            return false;
        }

        // Extract the users email from the cert.
        // First see if we have subjectAltNames extension
        String email = null;
        byte[] subjAltNameValue = ((X509Certificate) incert).getExtensionValue("2.5.29.17");

        // If not, see if we have old styld email-in-DN
        if (subjAltNameValue == null) {
            email = CertTools.getPartFromDN(dn, "EmailAddress");
        } else {
            try {
                // Get extension value
                ByteArrayInputStream bIn = new ByteArrayInputStream(subjAltNameValue);
                DEROctetString asn1 = (DEROctetString) new DERInputStream(bIn).readObject();
                ByteArrayInputStream bIn1 = new ByteArrayInputStream(asn1.getOctets());
                ASN1Sequence san = (ASN1Sequence) new DERInputStream(bIn1).readObject();

                for (int i = 0; i < san.size(); i++) {
                    DERTaggedObject gn = (DERTaggedObject) san.getObjectAt(i);
                    if (gn.getTagNo() == 1) {
                        // This is rfc822Name!
                        DERIA5String str;
                        if (gn.getObject() instanceof DERIA5String) {
                            str = (DERIA5String) gn.getObject();
                        } else {
                            str = new DERIA5String(((DEROctetString) gn.getObject()).getOctets());
                        }
                        email = str.getString();
                    }
                }
            } catch (IOException e) {
                error("IOException when getting subjectAltNames extension.");
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                    "IOException when getting subjectAltNames extension.");
            }
        }
        /*
        if (checkContainerName(dn) == false) {
            info("DN not part of containername, aborting store operation.");                                                         
            logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                    "DN not part of containername, aborting store operation.");            
            return false;
        }
        */

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = null;

        try {
            // connect to the server
            lc.connect(ldapHost, ldapPort);
            // authenticate to the server
            lc.bind(ldapVersion, loginDN, loginPassword);
            // try to read the old object
            oldEntry = lc.read(dn);
            // disconnect with the server
            lc.disconnect();
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                debug("No old entry exist for '" + dn + "'.");
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,
                        "No old entry exist for '" + dn + "'.");                
            } else {
                error("Error binding to and reading from LDAP server: ", e);
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                       (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                       "Error binding to and reading from LDAP server.");                
                return false;
            }
        }

        LDAPEntry newEntry = null;
        LDAPModificationSet modSet = null;
        LDAPAttributeSet attributeSet = null;
        String attribute = null;
        String objectclass = null;

        if (type == SecConst.CERTTYPE_ENDENTITY) {
            debug("Publishing end user certificate to " + ldapHost);

            if (oldEntry != null) {
                // TODO: Are we the correct type objectclass?
                modSet = getModificationSet(oldEntry, dn, false, true);
            } else {
                objectclass = userObjectclass;
            }

            attributeSet = getAttributeSet(userObjectclass, dn, true, true);
            if (email != null) {
                LDAPAttribute mailAttr = new LDAPAttribute("mail", email);
                if (oldEntry != null) {
                    modSet.add(LDAPModification.REPLACE, mailAttr);
                } else {
                    attributeSet.add(mailAttr);
                }
            }

            try {
                attribute = userCertAttribute;
                LDAPAttribute certAttr = new LDAPAttribute(userCertAttribute, incert.getEncoded());
                if (oldEntry != null) {
                    modSet.add(LDAPModification.REPLACE, certAttr);
                } else {
                    attributeSet.add(certAttr);
                }
            } catch (CertificateEncodingException e) {
                error("Error encoding certificate when storing in LDAP: ", e);
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                       (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                       "Error encoding certificate when storing in LDAP.");
                return false;
            }
        } else if ((type == SecConst.CERTTYPE_SUBCA) || (type == SecConst.CERTTYPE_ROOTCA)) {
            debug("Publishing CA certificate to " + ldapHost);

            if (oldEntry != null) {
                modSet = getModificationSet(oldEntry, dn, false, false);
            } else {
                objectclass = cAObjectclass;
            }
            attributeSet = getAttributeSet(cAObjectclass, dn, true, false);
            try {
                attribute = cACertAttribute;
                LDAPAttribute certAttr = new LDAPAttribute(cACertAttribute, incert.getEncoded());
                if (oldEntry != null) {
                    modSet.add(LDAPModification.REPLACE, certAttr);
                } else {
                    attributeSet.add(certAttr);
                    // Also create using the crlattribute, it may be required
                    LDAPAttribute crlAttr = new LDAPAttribute(cRLAttribute, "null".getBytes());
                    attributeSet.add(crlAttr);
                    // Also create using the arlattribute, it may be required
                    LDAPAttribute arlAttr = new LDAPAttribute(aRLAttribute, "null".getBytes());
                    attributeSet.add(arlAttr);
                    debug("Added (fake) attribute for CRL and ARL.");
                }
            } catch (CertificateEncodingException e) {
                error("Error encoding certificate when storing in LDAP: ", e);
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                        "Error encoding certificate when storing in LDAP.");
                return false;
            }
        } else {
            info("Certificate of type '" + type + "' will not be published.");
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                    "Certificate of type '" + type + "' will not be published.");          
            return false;
        }

        try {
            // connect to the server
            lc.connect(ldapHost, ldapPort);
            // authenticate to the server
            lc.bind(ldapVersion, loginDN, loginPassword);
            // Add or modify the entry
            if (oldEntry != null) {
                lc.modify(dn, modSet);
                debug("\nModified object: " + dn + " successfully.");  
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,
                        "Modified object: " + dn + " successfully in LDAP.");
            } else {
                if (oldEntry == null) {
                    newEntry = new LDAPEntry(dn, attributeSet);
                }
                lc.add(newEntry);
                debug("\nAdded object: " + dn + " successfully.");
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,
                        "Added object: " + dn + " successfully in LDAP.");
            }
            // disconnect with the server
            lc.disconnect();
        } catch (LDAPException e) {
            error("Error storing certificate (" + attribute + ") in LDAP (" + objectclass + "): ", e);  
             logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                    "Error storing certificate (" + attribute + ") in LDAP (" + objectclass + ").");
            return false;
        }
        debug("<storeCertificate()");
        return true;
    } // storeCertificate

    /**
     * Revokes a certificate (already revoked by the CA), the Publisher decides what to do, if
     * anything.
     *
     * @param admin administrator performing this action
     * @param cert The DER coded Certificate that has been revoked.
     * @param reason reason for revocation of the certificate
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void revokeCertificate(Admin admin, Certificate cert, int reason) {
        // TODO: remove revoked certificate from LDAP
    } //revokeCertificate

    /**
     * Published a CRL to LDAP. Creates CA entry if it does not exist.
     *
     * @param admin administrator performing this action
     * @param incrl The DER coded CRL to be stored.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     *
     * @return true if storage was successful.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) {
        int ldapVersion = LDAPConnection.LDAP_V3;
        LDAPConnection lc = new LDAPConnection();
        X509CRL crl = null;
        String dn = null;

        try {
            crl = CertTools.getCRLfromByteArray(incrl);

            // Extract the users DN from the crl.
            dn = CertTools.getIssuerDN(crl);
        } catch (Exception e) {
            error("Error decoding input CRL: ", e);
            
            logsession.log(admin, admin.getCAId(),LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL, "Error decoding input CRL.");


            return false;
        }
        /*
        if (checkContainerName(dn) == false) {
            info("DN not part of containername, aborting store operation.");
            
                logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL,
                    "DN not part of containername, aborting store operation.");


            return false;
        }
        */

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = null;
        try {
            // connect to the server
            lc.connect(ldapHost, ldapPort);
            // authenticate to the server
            lc.bind(ldapVersion, loginDN, loginPassword);
            // try to read the old object
            oldEntry = lc.read(dn);
            // disconnect with the server
            lc.disconnect();
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                debug("No old entry exist for '" + dn + "'.");
            } else {
                error("Error binding to and reading from LDAP server: ", e);
                logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_STORECRL,
                        "Error binding to and reading from LDAP server.");
                return false;
            }
        }

        LDAPEntry newEntry = null;
        LDAPModificationSet modSet = null;
        LDAPAttributeSet attributeSet = null;

        if (oldEntry != null) {
            modSet = getModificationSet(oldEntry, dn, false, false);
        } else {
            attributeSet = getAttributeSet(cAObjectclass, dn, true, false);
        }

        try {
            LDAPAttribute crlAttr = new LDAPAttribute(cRLAttribute, crl.getEncoded());
            LDAPAttribute arlAttr = new LDAPAttribute(aRLAttribute, crl.getEncoded());
            if (oldEntry != null) {
                modSet.add(LDAPModification.REPLACE, crlAttr);
                modSet.add(LDAPModification.REPLACE, arlAttr);
            } else {
                attributeSet.add(crlAttr);
                attributeSet.add(arlAttr);
            }
        } catch (CRLException e) {
            error("Error encoding CRL when storing in LDAP: ", e);
            logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL, "Error encoding CRL when storing in LDAP.");
            return false;
        }

        if (oldEntry == null) {
            newEntry = new LDAPEntry(dn, attributeSet);
        }

        try {
            // connect to the server
            lc.connect(ldapHost, ldapPort);
            // authenticate to the server
            lc.bind(ldapVersion, loginDN, loginPassword);
            // Add or modify the entry
            if (oldEntry != null) {
                lc.modify(dn, modSet);
                debug("\nModified object: " + dn + " successfully.");
                logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_INFO_STORECRL,
                        "Modified object: " + dn + " successfully in LDAP.");
            } else {
                lc.add(newEntry);
                debug("\nAdded object: " + dn + " successfully.");
                logsession.log(admin, crl.getIssuerDN().toString().hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_INFO_STORECRL,
                        "Added object: " + dn + " successfully in LDAP.");
            }

            // disconnect with the server
            lc.disconnect();
        } catch (LDAPException e) {
            error("Error storing CRL (" + cRLAttribute + ") in LDAP (" + cAObjectclass + "): ", e);
            logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL,
                    "Error storing CRL (" + cRLAttribute + ") in LDAP (" + cAObjectclass + ").");            
            return false;
        }

        return true;
    } // storeCRL
    
    private boolean checkContainerName(String dn) {
        // Match users DN with 'containerName'?
        // Normalize string lo BC DN format to avoide different case in o, C etc.
        // TODO: if containerName consists of dc attributes?
        if (dn.indexOf(CertTools.stringToBCDNString(containerName)) == -1) {
            info("SubjectDN '" + dn + "' is not part of containerName '" + containerName +
                "' for LDAP server.");

            return false;
        }

        return true;
    } // checkContainerName

    /**
     * Creates an LDAPAttributeSet.
     *
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @param pserson true if this is a person-entry, false if it is a CA.
     *
     * @return LDAPAtributeSet created...
     */
    private LDAPAttributeSet getAttributeSet(String objectclass, String dn, boolean extra, boolean person) {
        LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        LDAPAttribute attr = new LDAPAttribute("objectclass");
        // The full LDAP object tree is divided with ; in the objectclass
        StringTokenizer token = new StringTokenizer(objectclass,";");
        while (token.hasMoreTokens()) {
            String value = token.nextToken();
            debug("Adding objectclass value: "+value);
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
            // sn means surname in LDAP, and is required for persons
            String sn = CertTools.getPartFromDN(dn, "SURNAME");
            if (person) {
                if ( (sn == null) && (cn != null) ) {
                    // Take surname to be the last part of the cn
                    int index = cn.indexOf(' ');
                    if (index <=0) {
                        // If there is no natural sn, use cn since sn is required
                        sn = cn;
                    } else {
                        if (index < cn.length()) sn = cn.substring(index);
                    }
                }
            }
            if (sn != null) {
                attributeSet.add(new LDAPAttribute("sn", sn));
            }
            // gn means givenname in LDAP, and is required for persons
            String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
            if (person) {
                if ( (gn == null) && (cn != null) ) {
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
                attributeSet.add(new LDAPAttribute("gn", gn));
            }
            String l = CertTools.getPartFromDN(dn, "L");
            if (l != null) {
                attributeSet.add(new LDAPAttribute("l", l));
            }
            String st = CertTools.getPartFromDN(dn, "ST");
            if (st != null) {
                attributeSet.add(new LDAPAttribute("st", st));
            }
            String ou = CertTools.getPartFromDN(dn, "OU");
            if (ou != null) {
                attributeSet.add(new LDAPAttribute("ou", ou));
            }
        }
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
    private LDAPModificationSet getModificationSet(LDAPEntry oldEntry, String dn, boolean extra, boolean person) {
        LDAPModificationSet modSet = new LDAPModificationSet();

        if (extra) {
            String cn = CertTools.getPartFromDN(dn, "CN");
            if (cn != null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("cn", cn));
            }
            // sn means surname in LDAP, and is required for persons
            String sn = CertTools.getPartFromDN(dn, "SURNAME");
            if (person) {
                if ( (sn == null) && (cn != null) ) {
                    // Take surname to be the last part of the cn
                    int index = cn.indexOf(' ');
                    if (index <=0) {
                        // If there is no natural sn, use cn since sn is required
                        sn = cn;
                    } else {
                        if (index < cn.length()) sn = cn.substring(index);
                    }
                }
            }
            if (sn != null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("sn", sn));
            }
            // gn means givenname in LDAP, and is required for persons
            String gn = CertTools.getPartFromDN(dn, "GIVENNAME");
            if (person) {
                if ( (gn == null) && (cn != null) ) {
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
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("gn", gn));
            }
            String l = CertTools.getPartFromDN(dn, "L");
            if (l != null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("l", l));
            }
            String st = CertTools.getPartFromDN(dn, "ST");
            if (st != null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("st", st));
            }
            String ou = CertTools.getPartFromDN(dn, "OU");
            if (ou != null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute("ou", ou));
            }
        }
        return modSet;
    } // getModificationSet
}
