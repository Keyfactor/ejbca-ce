
package se.anatom.ejbca.ca.store;

import java.rmi.*;
import javax.rmi.*;
import javax.ejb.*;
import java.io.*;

import com.novell.ldap.*;

import java.security.cert.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.util.*;

/**
 * Stores certificates and CRL in an LDAP v3 directory.
 *
 * <p>LDAP schema required:<br>
 * Certificates are published as 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * CRLs are published as 'certificateRevocationList' in objectclass 'certificationAuthority'.
 *
 * <p>In inetOrgPerson the following attributes are set if present in the certificate:
 * <pre>
 * cn
 * ou
 * l
 * st
 * sn
 * mail
 * userCertificate
 * </pre>
 *
 * @version $Id: LDAPPublisherSessionBean.java,v 1.2 2002-01-06 10:51:32 anatom Exp $
 */
public class LDAPPublisherSessionBean extends BaseSessionBean implements IPublisherSession {

    private String ldapHost       = "localhost";       
    private int ldapPort          = LDAPConnection.DEFAULT_PORT;
    private String loginDN        = "cn=Admin,o=AnaTom,c=SE";
    private String loginPassword  = "foo123";
    private String containerName  = "o=AnaTom,c=SE";

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        ldapHost = (String)lookup("java:comp/env/ldapHost", java.lang.String.class);
        ldapPort = ( (Integer)lookup("java:comp/env/ldapPort", java.lang.Integer.class) ).intValue();
        loginDN = (String)lookup("java:comp/env/loginDN", java.lang.String.class);
        loginPassword = (String)lookup("java:comp/env/loginPassword", java.lang.String.class);
        containerName = (String)lookup("java:comp/env/containerName", java.lang.String.class);
        debug("ldapHost=" + ldapHost);
        debug("loginDN=" + loginDN);
        debug("loginPassword=" + loginPassword);
        debug("containerName=" + containerName);
        debug("<ejbCreate()");
    }

    /**
     * Published a CRL to LDAP. Creates CA entry if it does not exist.
     *
     * @param incrl The CRL to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     *
     * @return true if storage was succesful.
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCRL(X509CRL incrl, String cafp, int number) throws RemoteException {
        
        // TODO:
        
        return false;
    } // storeCRL
    
    /**
     * Publishes a certificate to LDAP. Creates entry if it does not exist.
     *
     * @param incert The certificate to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     *
     * @return true if storage was succesful.
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCertificate(Certificate incert, String cafp, int status, int type) throws RemoteException {

        int ldapVersion  = LDAPConnection.LDAP_V3;             
        LDAPConnection lc = new LDAPConnection();

     
        // Extract the users DN from the cert.
        String dn = CertTools.stringToBCDNString(((X509Certificate)incert).getSubjectDN().toString());
        
        // Extract the users email from the cert.
        // First see if we have subjectAltNames extension
        String email = null;
        byte[] subjAltNameValue = ((X509Certificate)incert).getExtensionValue("2.5.29.17");
        // If not, see if we have old styld email-in-DN
        if (subjAltNameValue == null)
            email = CertTools.getPartFromDN(dn, "EmailAddress");
        else {
            try {
                // Get extension value
                ByteArrayInputStream bIn = new ByteArrayInputStream(subjAltNameValue);
                DERConstructedSequence san = (DERConstructedSequence)new DERInputStream(bIn).readObject();
                for (int i=0;i<san.getSize();i++) {
                    DERTaggedObject gn = (DERTaggedObject)san.getObjectAt(i);
                    if (gn.getTagNo() == 1) {
                        // This is rfc822Name!
                        DERIA5String str = (DERIA5String)gn.getObject();
                        email = str.getString();
                    }
                }
            } catch (IOException e) {
                error("IOException when getting subjectAltNames extension.");
            }
            
        }
        
        // Match users DN with 'containerName'?
        // Normalize string lo lower case so we don't care about matching case (we are not THAT picky about
        // different case inside O,C etc, it will fail later in that case.
        if (dn.toLowerCase().indexOf(containerName.toLowerCase()) == -1)
        {
            info("SubjectDN '"+dn+"' is not part of containerName '"+containerName+"' for LDAP server.");
            return false;
        }
        
        // TODO: different objectclasses for different certificate types
        // CA etc.
        
        /* To Add an entry to the directory,
         *   -- Create the attributes of the entry and add them to an attribute set
         *   -- Specify the DN of the entry to be created
         *   -- Create an LDAPEntry object with the DN and the attribute set
         *   -- Call the LDAPConnection add method to add it to the directory
         */           
        LDAPAttributeSet attributeSet = getAttributeSet("inetOrgPerson", dn);
        if (email != null)
            attributeSet.add( new LDAPAttribute( "mail", email ) ); 
        try {
            attributeSet.add( new LDAPAttribute( "userCertificate;binary", incert.getEncoded() ) );
        } catch (CertificateEncodingException e) {
            error("Error encoding certificate when storing in LDAP: ",e);
            return false;
        }
        LDAPEntry newEntry = new LDAPEntry( dn, attributeSet );
        try {  
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );

            lc.add( newEntry );
            debug( "\nAdded object: " + dn + " successfully." );

            // disconnect with the server
            lc.disconnect();
        }
        catch( LDAPException e ) {
            error( "Error storing certificate in LDAP: ", e);
            return false;
        }   
        
        // TODO: If the entry was already present, we will update it with the new certificate.
        
        return true;
    } // storeCertificate
    
    private LDAPAttributeSet getAttributeSet(String objectclass, String dn) 
    {
        LDAPAttributeSet attributeSet = new LDAPAttributeSet();

        attributeSet.add( new LDAPAttribute( "objectclass", objectclass ) );      
        String cn = CertTools.getPartFromDN(dn,"CN");
        if (cn!=null)
            attributeSet.add(new LDAPAttribute( "cn", cn));
        String sn = CertTools.getPartFromDN(dn,"SN");
        if (sn!=null)
            attributeSet.add( new LDAPAttribute( "sn", sn ) );
        String l = CertTools.getPartFromDN(dn,"L");
        if (l!=null)
            attributeSet.add( new LDAPAttribute( "l", l ) );
        String st = CertTools.getPartFromDN(dn,"ST");
        if (st!=null)
            attributeSet.add( new LDAPAttribute( "st", st ) );
        String ou = CertTools.getPartFromDN(dn,"OU");
        if (ou!=null)
            attributeSet.add( new LDAPAttribute( "ou", ou ) );
            
        return attributeSet;
    } // getAttributeSet
}
