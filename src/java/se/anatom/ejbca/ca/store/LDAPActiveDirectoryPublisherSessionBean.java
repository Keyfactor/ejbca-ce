package se.anatom.ejbca.ca.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;


/**
 * Stores certificates and CRL in an MS Active Directory (LDAP v3). This file is tested using IBMs
 * directory Factory from VisualAge, but should be possbile to get to work with other directory
 * factories as well.
 * 
 * <p>
 * LDAP schema required:<br>
 * Certificates for CERTTYPE_ENDENTITY are published as attribute 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * Certificates for CERTTYPE_CA andCERTTYPE_ROOTCA are published as attribute cACertificate in
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
 * @version $Id: LDAPActiveDirectoryPublisherSessionBean.java,v 1.18 2003-09-04 06:46:05 anatom Exp $
 */
public class LDAPActiveDirectoryPublisherSessionBean extends BaseSessionBean {
    private String ldapHost = "10.1.1.1";
    private int ldapPort = 389;
    private String loginDN = "cn=user,cn=Users,dc=foo,dc=bar";
    private String loginPassword = "password";
    private String containerName = "cn=EJBCA,dc=foo,dc=bar";

    //For Microsoft Active directory
    private String userObjectclass = "user";

    //For Microsoft Active directory
    private String cAObjectclass = "certificationAuthority";

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

        debug("ldapHost=" + ldapHost);
        debug("loginDN=" + loginDN);
        debug("loginPassword=" + loginPassword);
        debug("containerName=" + containerName);
        debug("userObjectclass=" + userObjectclass);
        debug("cAObjectclass=" + cAObjectclass);

        try {
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",
                    ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
        } catch (Exception e) {
            throw new EJBException(e);
        }

        debug("<ejbCreate()");
    }

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
    }

    // checkContainerName

    /**
     * DOCUMENT ME!
     *
     * @param admin DOCUMENT ME!
     * @param byte_incert DOCUMENT ME!
     * @param cafp DOCUMENT ME!
     * @param status DOCUMENT ME!
     * @param type DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type) 
        throws RemoteException {
        String dn = null;
        String cn = null;
        try {
            // Extract the users DN from the cert.
            dn = CertTools.getSubjectDN((X509Certificate) incert);
            cn = CertTools.getPartFromDN(dn, "CN");
        } catch (Exception e) {
            debug("Error decoding input Certificate: ", e);
            
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                    "Error decoding input Certificate.");           

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
                debug("IOException when getting subjectAltNames extension.");

                
                logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                        "IOException when getting subjectAltNames extension.");
            }
        }

        //We don't check the ContainerName for Active Directory, so comment it out
        //The reason is ,CertTools.stringToBcX509Name() can't deal with Active Directory Name.
        //if (checkContainerName(dn) == false)
        //  return false;
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.ibm.jndi.LDAPCtxFactory");
        env.put(Context.SECURITY_PRINCIPAL, loginDN);
        env.put(Context.SECURITY_CREDENTIALS, loginPassword);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, "ldap://" + ldapHost + ":" + ldapPort + "/" + containerName);

        /* //Can only set password through SSL connection, comment it out if needed
        if (ldapPort == 636) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            env.put("java.naming.security.ssl.keyring", "TestClient");
            env.put("java.naming.security.ssl.authentication", "WebAS");
        }
        */
        Attributes oldEntry = null;

        try {
            // Create the initial directory context
            DirContext ctx = new InitialDirContext(env);

            // Ask for all attributes of the object
            oldEntry = ctx.getAttributes("CN=" + cn);
            ctx.close();
        } catch (NamingException e) {
        }

        if (type == SecConst.CERTTYPE_ENDENTITY) {
            if (oldEntry == null) {
                try {
                    // Create the initial directory context
                    DirContext ctx = new InitialDirContext(env);

                    // Create a new attribute set for the entry.
                    BasicAttributes attrs = new BasicAttributes();
                    BasicAttribute ocs = new BasicAttribute("objectclass");
                    ocs.add("top");
                    ocs.add("person");
                    ocs.add("organizationalPerson");
                    ocs.add(userObjectclass);
                    attrs.put(ocs);

                    // cn and samaccountname is the attributes must set in Active Directory for objectclass user.
                    attrs.put(new BasicAttribute("givenName", cn));
                    attrs.put(new BasicAttribute("sn", cn));
                    attrs.put(new BasicAttribute("cn", cn));

                    // Set password to be never expired.  512 : indicates password should be changed after login
                    attrs.put(new BasicAttribute("userAccountControl", "66048"));
                    attrs.put(new BasicAttribute("samaccountname", cn));
                    attrs.put(new BasicAttribute("userPrincipalName", cn));
                    attrs.put(new BasicAttribute("displayName", cn));
                    attrs.put(new BasicAttribute("description", "Test User created through JNDI"));

                    /*
                    //Can only set password through SSL connection, comment it out if needed
                        attrs.put(new BasicAttribute("userPassword", cn));

                        //Start out by taking the password and enclosing it in quotes, as in
                        String newVal = new String("\"" + cn + "\"");

                        //Then, you need to get the octet string of the Unicode representation of
                        //that.  You need to leave off the extra two bytes Java uses as length:
                        byte _bytes[] = newVal.getBytes("Unicode");
                        byte bytes[] = new byte[_bytes.length - 2];
                        System.arraycopy(_bytes, 2, bytes, 0, _bytes.length - 2);

                        //Take that value and stuff it into the unicodePwd attribute:
                        BasicAttribute attribute = new BasicAttribute("unicodePwd");
                        attribute.add((byte[]) bytes);
                        attrs.put(attribute);
                        */
                    if (email != null) {
                        attrs.put(new BasicAttribute("mail", email));
                    }

                    attrs.put(new BasicAttribute("userCertificate;binary", incert.getEncoded()));

                    // Create an entry with this DN and these attributes .
                    ctx.createSubcontext("CN=" + cn, attrs);

                    ctx.close();
                } catch (Exception e) {
                    debug("Error storing certificate in Active Directory LDAP: ", e);
                   
                      logsession.log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                            (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                            "Error storing certificate in Active Directory LDAP.");


                    return false;
                }
            } else {
                try {
                    // Create the initial directory context
                    DirContext ctx = new InitialDirContext(env);

                    BasicAttributes attrs = new BasicAttributes();

                    if (email != null) {
                        attrs.put(new BasicAttribute("mail", email));
                    }

                    attrs.put(new BasicAttribute("userCertificate;binary", incert.getEncoded()));

                    ctx.modifyAttributes("CN=" + cn, DirContext.REPLACE_ATTRIBUTE, attrs);
                    ctx.close();
                } catch (Exception e) {
                    debug("Error storing certificate in Active Directory LDAP: ", e);

                     logsession.log(admin,  (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), null,
                            (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                            "Error storing certificate in Active Directory LDAP.");


                    return false;
                }
            }
        } else if ((type == SecConst.CERTTYPE_SUBCA) || (type == SecConst.CERTTYPE_ROOTCA)) {
            try {
                // Create the initial directory context
                DirContext ctx = new InitialDirContext(env);

                // Create a new attribute set for the entry.
                BasicAttributes attrs = new BasicAttributes();
                BasicAttribute ocs = new BasicAttribute("objectclass");
                ocs.add("top");
                ocs.add(cAObjectclass);
                attrs.put(ocs);

                attrs.put(new BasicAttribute("cACertificate;binary", incert.getEncoded()));

                //Must set the two CRL attributes for Active Directory, so retrieve last CRL
                // in local store instead.
                ICertificateStoreSessionHome storeHome = null;

                try {
                    InitialContext stctx = new InitialContext();
                    storeHome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(stctx.lookup(
                                "CertificateStoreSession"),
                            ICertificateStoreSessionHome.class);
                } catch (NamingException exc) {
                    error("Error retrieving the home of  CertificateData or CRLData.", exc);

                    return false;
                }

                ICertificateStoreSessionRemote localstore = storeHome.create();
                byte[] lastcrl = localstore.getLastCRL(admin, ((X509Certificate) incert).getSubjectDN().toString());
                attrs.put(new BasicAttribute("certificateRevocationList;binary", lastcrl));
                attrs.put(new BasicAttribute("authorityRevocationList;binary", lastcrl));

                //Destroy old entry if exists, Active Directory doesn't allow modification.
                if (oldEntry != null) {
                    ctx.destroySubcontext("CN=" + cn);
                }

                // Create an entry with this DN and these attributes .
                ctx.createSubcontext("CN=" + cn, attrs);

                ctx.close();
            } catch (Exception e) {
                debug("Error storing certificate in Active Directory LDAP: ", e);

                    logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null,
                        (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,
                        "Error storing certificate in Active Directory LDAP.");

                return false;
            }
        }

        return true;
    }

    // storeCertificate

    /**
     * Revokes a certificate (already revoked by the CA), the Publisher decides what to do, if
     * anything.
     *
     * @param admin DOCUMENT ME!
     * @param cert The DER coded Certificate that has been revoked.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void revokeCertificate(Admin admin, Certificate cert) {
        // TODO: remove revoked certificate from LDAP
    }

    //revokeCertificate

    /**
     * DOCUMENT ME!
     *
     * @param admin DOCUMENT ME!
     * @param incrl DOCUMENT ME!
     * @param cafp DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)
        throws RemoteException {
        X509CRL crl = null;
        String dn = null;
        String cn = null;

        try {
            crl = CertTools.getCRLfromByteArray(incrl);

            // Extract the users DN from the crl.
            dn = CertTools.getIssuerDN(crl);
            cn = CertTools.getPartFromDN(dn, "CN");
        } catch (Exception e) {
            debug("Error decoding input CRL: ", e);
            
           logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL, "Error decoding input CRL.");            

            return false;
        }

        //We don't check the ContainerName for Active Directory, so comment it out
        //The reason is ,CertTools.stringToBcX509Name() can't deal with Active Directory Name.
        //if (checkContainerName(dn) == false)
        //  return false;
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.ibm.jndi.LDAPCtxFactory");
        env.put(Context.SECURITY_PRINCIPAL, loginDN);
        env.put(Context.SECURITY_CREDENTIALS, loginPassword);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, "ldap://" + ldapHost + ":" + ldapPort + "/" + containerName);

        try {
            // Create the initial directory context
            DirContext ctx = new InitialDirContext(env);

            // Ask for all attributes of the object
            //oldEntry = ctx.getAttributes("CN=" + cn);
            //Destroy old entry if exists, Active Directory doesn't allow modification.
            ctx.destroySubcontext("CN=" + cn);
            ctx.close();
        } catch (NamingException e) {
        }

        try {
            // Create the initial directory context
            DirContext ctx = new InitialDirContext(env);

            // Create a new attribute set for the entry.
            BasicAttributes attrs = new BasicAttributes();
            BasicAttribute ocs = new BasicAttribute("objectclass");
            ocs.add("top");
            ocs.add(cAObjectclass);
            attrs.put(ocs);

            //Must set the cACertificate attribute for Active Directory, so retrieve from RSASignSession bean.
            ISignSessionHome signHome = null;

            try {
                InitialContext stctx = new InitialContext();
                signHome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(stctx.lookup(
                            "RSASignSession"), ISignSessionHome.class);
            } catch (NamingException exc) {
                error("Error retrieving the home of CertificateData or CRLData.", exc);

                return false;
            }

            ISignSessionRemote rsasign = signHome.create();
            Iterator certchain = rsasign.getCertificateChain(admin, crl.getIssuerDN().toString().hashCode()).iterator();

            //Use CA's certificate.
            attrs.put(new BasicAttribute("cACertificate;binary", ((Certificate) certchain.next()).getEncoded()));

            attrs.put(new BasicAttribute("certificateRevocationList;binary", incrl));
            attrs.put(new BasicAttribute("authorityRevocationList;binary", incrl));

            // Create an entry with this DN and these attributes .
            ctx.createSubcontext("CN=" + cn, attrs);

            ctx.close();

            return true;
        } catch (Exception e) {
            debug("Error storing CRL in Active Directory LDAP: ", e);           
              logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL, "Error storing CRL in Active Directory LDAP.");
            
        }

        return false;
    }
}
