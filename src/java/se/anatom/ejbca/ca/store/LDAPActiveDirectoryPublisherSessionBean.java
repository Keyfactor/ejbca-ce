package se.anatom.ejbca.ca.store;

import java.rmi.*;
import javax.rmi.*;
import javax.ejb.*;
import java.io.*;
import java.util.*;

import javax.naming.*;
import javax.naming.ldap.*;
import javax.naming.directory.*;

//import com.novell.ldap.*;

import java.security.cert.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.sign.*;
import se.anatom.ejbca.util.*;
import java.util.Properties;

import org.apache.log4j.*;

/**
 * Stores certificates and CRL in an MS Active Directory (LDAP v3).
 * This file is tested using IBMs directory Factory from VisualAge, but should be possbile
 * to get to work with other directory factories as well.
 *
 * <p>LDAP schema required:<br>
 * Certificates for USER_ENDUSER, USER_RA, USER_RAADMIN, USER_CAADMIN are published
 * as attribute 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * Certificates for USER_CA and USER_ROOTCA are published as attribute cACertificate in
 * objectclass 'certificationAuthority'.<br>
 * CRLs are published as attribute 'certificateRevocationList' in objectclass
 * 'certificationAuthority'.
 *
 * <p>In 'inetOrgPerson' the following attributes are set if present in the certificate:
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
 * <p>In 'certificationAuthority' the only attributes set are:
 * <pre>
 * DN
 * cACertificate
 * </pre>
 *
 * @version $Id: LDAPActiveDirectoryPublisherSessionBean.java,v 1.1 2002-08-07 08:33:45 anatom Exp $
 */
public class LDAPActiveDirectoryPublisherSessionBean
    extends BaseSessionBean {

    private String ldapHost = "10.1.1.1";
    private int ldapPort = 389;
    private String loginDN = "cn=user,cn=Users,dc=foo,dc=bar";
    private String loginPassword = "password";
    private String containerName = "cn=EJBCA,dc=foo,dc=bar";
    //For Microsoft Active directory
    private String userObjectclass = "user";
    //For Microsoft Active directory
    private String cAObjectclass = "certificationAuthority";

    /**
         * Default create for SessionBean without any creation Arguments.
         * @throws CreateException if bean instance can't be created
         */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        Properties prp = getSessionContext().getEnvironment();
        if (prp.getProperty("ldapHost") != null)
            ldapHost = prp.getProperty("ldapHost");
        if (prp.getProperty("ldapPort") != null)
            ldapPort = (new Integer(prp.getProperty("ldapPort"))).intValue();
        if (prp.getProperty("loginDN") != null)
            loginDN = prp.getProperty("loginDN");
        if (prp.getProperty("loginPassword") != null)
            loginPassword = prp.getProperty("loginPassword");
        if (prp.getProperty("containerName") != null)
            containerName = prp.getProperty("containerName");
        if (prp.getProperty("userObjectclass") != null)
            userObjectclass = prp.getProperty("userObjectclass");
        if (prp.getProperty("cAObjectclass") != null)
            cAObjectclass = prp.getProperty("cAObjectclass");

        debug("ldapHost=" + ldapHost);
        debug("loginDN=" + loginDN);
        debug("loginPassword=" + loginPassword);
        debug("containerName=" + containerName);
        debug("userObjectclass=" + userObjectclass);
        debug("cAObjectclass=" + cAObjectclass);

        debug("<ejbCreate()");
    }

    private boolean checkContainerName(String dn)
    {
        // Match users DN with 'containerName'?
        // Normalize string lo BC DN format to avoide different case in o, C etc.
        // TODO: if containerName consists of dc attributes?
        if (dn.indexOf(CertTools.stringToBCDNString(containerName)) == -1)
        {
            info("SubjectDN '"+dn+"' is not part of containerName '"+containerName+"' for LDAP server.");
            return false;
        }
        return true;
    } // checkContainerName

    public boolean storeCertificate(
        byte[] byte_incert,
        String cafp,
        int status,
        int type)
        throws RemoteException {
        Certificate incert = null;
        try {
            incert = CertTools.getCertfromByteArray(Base64.decode(byte_incert));
        } catch (Exception e) {
            error("Error decoding input Certificate: ", e);
            return false;
        }

        // Extract the users DN from the cert.
        String dn =
            CertTools.stringToBCDNString(
                ((X509Certificate) incert).getSubjectDN().toString());
        String cn = CertTools.getPartFromDN(dn, "CN");

        // Extract the users email from the cert.
        // First see if we have subjectAltNames extension
        String email = null;
        byte[] subjAltNameValue =
            ((X509Certificate) incert).getExtensionValue("2.5.29.17");
        // If not, see if we have old styld email-in-DN
        if (subjAltNameValue == null)
            email = CertTools.getPartFromDN(dn, "EmailAddress");
        else {
            try {
                // Get extension value
                ByteArrayInputStream bIn = new ByteArrayInputStream(subjAltNameValue);
                DEROctetString asn1 = (DEROctetString) new DERInputStream(bIn).readObject();
                ByteArrayInputStream bIn1 = new ByteArrayInputStream(asn1.getOctets());
                DERConstructedSequence san =
                    (DERConstructedSequence) new DERInputStream(bIn1).readObject();
                for (int i = 0; i < san.getSize(); i++) {
                    DERTaggedObject gn = (DERTaggedObject) san.getObjectAt(i);
                    if (gn.getTagNo() == 1) {
                        // This is rfc822Name!
                        DERIA5String str;
                        if (gn.getObject() instanceof DERIA5String)
                            str = (DERIA5String) gn.getObject();
                        else
                            str = new DERIA5String(((DEROctetString) gn.getObject()).getOctets());
                        email = str.getString();
                    }
                }
            } catch (IOException e) {
                error("IOException when getting subjectAltNames extension.");
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
        env.put(
            Context.PROVIDER_URL,
            "ldap://" + ldapHost + ":" + ldapPort + "/" + containerName);

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
        if (((type & SecConst.USER_ENDUSER) != 0)
            || ((type & SecConst.USER_CAADMIN) != 0)
            || ((type & SecConst.USER_RAADMIN) != 0)
            || ((type & SecConst.USER_RA) != 0)) {
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
                    error("Error storing certificate in LDAP: ", e);
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
                    error("Error storing certificate in LDAP: ", e);
                    return false;
                }

            }
        } else
            if (((type & SecConst.USER_CA) != 0) || ((type & SecConst.USER_ROOTCA) != 0))
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
                        storeHome =
                            (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(
                                stctx.lookup("se/anatom/ejbca/ca/store/ICertificateStoreSessionRemote"),
                                ICertificateStoreSessionHome.class);

                    } catch (NamingException exc) {
                        System.out.println("Error retrieving the home of  CertificateData or CRLData.");
                        exc.printStackTrace();
                    }
                    ICertificateStoreSessionRemote localstore = storeHome.create();
                    byte[] lastcrl = localstore.getLastCRL();
                    attrs.put(new BasicAttribute("certificateRevocationList;binary", lastcrl));
                    attrs.put(new BasicAttribute("authorityRevocationList;binary", lastcrl));

                    //Destroy old entry if exists, Active Directory doesn't allow modification.
                    if (oldEntry != null)
                        ctx.destroySubcontext("CN=" + cn);

                    // Create an entry with this DN and these attributes .
                    ctx.createSubcontext("CN=" + cn, attrs);

                    ctx.close();

                } catch (Exception e) {
                    error("Error storing certificate in LDAP: ", e);
                    return false;
                }

        return true;
    }
    // storeCertificate

    public boolean storeCRL(byte[] incrl, String cafp, int number)
        throws RemoteException {

        X509CRL crl;
        try {
            crl = CertTools.getCRLfromByteArray(incrl);
        } catch (Exception e) {
            error("Error decoding input CRL: ", e);
            return false;
        }

        // Extract the users DN from the cert.
        String dn = CertTools.stringToBCDNString(crl.getIssuerDN().toString());
        String cn = CertTools.getPartFromDN(dn, "CN");

        //We don't check the ContainerName for Active Directory, so comment it out
        //The reason is ,CertTools.stringToBcX509Name() can't deal with Active Directory Name.
        //if (checkContainerName(dn) == false)
        //  return false;

        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.ibm.jndi.LDAPCtxFactory");
        env.put(Context.SECURITY_PRINCIPAL, loginDN);
        env.put(Context.SECURITY_CREDENTIALS, loginPassword);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(
            Context.PROVIDER_URL,
            "ldap://" + ldapHost + ":" + ldapPort + "/" + containerName);

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
                signHome =
                    (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(
                        stctx.lookup("se/anatom/ejbca/ca/sign/ISignSessionRemote"),
                        ISignSessionHome.class);

            } catch (NamingException exc) {
                System.out.println("Error retrieving the home of  CertificateData or CRLData.");
                exc.printStackTrace();
                return false;
            }
            ISignSessionRemote rsasign = signHome.create();
            Certificate[] certchain = rsasign.getCertificateChain();

            //Use CA's certificate.
            attrs.put(
                new BasicAttribute(
                    "cACertificate;binary",
                    certchain[0].getEncoded()));

            attrs.put(new BasicAttribute("certificateRevocationList;binary", incrl));
            attrs.put(new BasicAttribute("authorityRevocationList;binary", incrl));

            // Create an entry with this DN and these attributes .
            ctx.createSubcontext("CN=" + cn, attrs);

            ctx.close();
            return true;

        } catch (Exception e) {
            error("Error storing CRL in LDAP: ", e);
        }
        return false;
    }
}
