
package se.anatom.ejbca.ca.store;

import java.rmi.*;
import javax.rmi.*;
import javax.ejb.*;

import com.novell.ldap.*;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.BaseSessionBean;

/**
 * Stores certificates and CRL in an LDAP v3 directory.
 *
 * <p>LDAP schema required:<br>
 * Certificates are published as 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * CRLs are published as 'certificateRevocationList' in objectclass 'certificationAuthority'.
 *
 * @version $Id: LDAPPublisherSessionBean.java,v 1.1 2002-01-05 15:50:11 anatom Exp $
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
        LDAPAttribute  attribute = null;
        LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        LDAPAttribute  certattribute = null;
        LDAPAttributeSet certattributeSet = new LDAPAttributeSet();

     
        // TODO: Extract the users DN from the cert.
        // Extract the ysers email from the cert.
        // Match users DN with 'containerName'?
        // TODO: Extract other stuff from certificate if present.
        
        /* To Add an entry to the directory,
         *   -- Create the attributes of the entry and add them to an attribute set
         *   -- Specify the DN of the entry to be created
         *   -- Create an LDAPEntry object with the DN and the attribute set
         *   -- Call the LDAPConnection add method to add it to the directory
         */           
        String objectclass_values[] = { "inetOrgPerson" };
        attribute = new LDAPAttribute( "objectclass", objectclass_values );
        attributeSet.add( attribute );      
        String cn_values[] = { "James Smith", "Jim Smith", "Jimmy Smith" };
        attribute = new LDAPAttribute( "cn", cn_values );
        attributeSet.add( attribute );
        String givenname_values[] = { "James", "Jim", "Jimmy" };
        attribute = new LDAPAttribute( "givenname", givenname_values );
        attributeSet.add( attribute );
        attributeSet.add( new LDAPAttribute( "sn", "Smith" ) );
        attributeSet.add( new LDAPAttribute( "telephonenumber",
                                                     "1 801 555 1212" ) );   
        attributeSet.add( new LDAPAttribute( "mail", "JSmith@Acme.com" ) );        
        //attributeSet.add( new LDAPAttribute( "userCertificate", incert ) );
        String  dn  = "cn=SmithJam," + containerName;      
        LDAPEntry newEntry = new LDAPEntry( dn, attributeSet );
        try {  
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );

            lc.add( newEntry );
            System.out.println( "\nAdded object: " + dn + " successfully." );

            // disconnect with the server
            lc.disconnect();
        }
        catch( LDAPException e ) {
            System.out.println( "Error: " + e.toString() );
        }   
        
        // TODO: If the entry was already present, we will update it with the new certificate.
        
        return false;
    } // storeCertificate
    
    
}
