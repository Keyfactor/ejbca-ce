package se.anatom.ejbca.ca.store;

import java.rmi.*;
import javax.ejb.*;
import java.io.*;

import com.novell.ldap.*;

import java.security.cert.*;

import org.bouncycastle.asn1.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.LogEntry;

/**
 * Stores certificates and CRL in an LDAP v3 directory.
 *
 * <p>LDAP schema required:<br>
 * Certificates for CERTTYPE_ENDENTITY are published
 * as attribute 'userCertificate' in objectclass 'inetOrgPerson'.<br>
 * Certificates for CERTTYPE_CA and CERTTYPE_ROOTCA are published as attribute cACertificate in
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
 * @version $Id: LDAPPublisherSessionBean.java,v 1.21 2003-06-13 16:34:32 anatom Exp $
 */
public class LDAPPublisherSessionBean extends BaseSessionBean {

    private String ldapHost       = "localhost";
    private int ldapPort          = LDAPConnection.DEFAULT_PORT;
    private String loginDN        = "cn=Admin,o=AnaTom,c=SE";
    private String loginPassword  = "foo123";
    private String containerName  = "o=AnaTom,c=SE";
    private String userObjectclass= "inetOrgPerson";
    private String cAObjectclass  = "certificateAuthority";
    private String cRLAttribute   = "certificateRevocationList;binary";
    private String userCertAttribute = "userCertificate;binary";
    private String cACertAttribute= "cACertificate;binary";

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;

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
        userObjectclass = (String)lookup("java:comp/env/userObjectclass", java.lang.String.class);
        cAObjectclass = (String)lookup("java:comp/env/cAObjectclass", java.lang.String.class);
        cRLAttribute = (String)lookup("java:comp/env/cRLAttribute", java.lang.String.class);
        userCertAttribute = (String)lookup("java:comp/env/userCertAttribute", java.lang.String.class);
        cACertAttribute = (String)lookup("java:comp/env/cACertAttribute", java.lang.String.class);
        debug("ldapHost=" + ldapHost);
        debug("loginDN=" + loginDN);
        debug("loginPassword=" + loginPassword);
        debug("containerName=" + containerName);
        debug("userObjectclass=" + userObjectclass);
        debug("cAObjectclass=" + cAObjectclass);
        debug("<ejbCreate()");

        try{
          ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);
          logsession = logsessionhome.create();
        }catch(Exception e){
          throw new EJBException(e);
        }
    }

    /**
     * Publishes a certificate to LDAP. Creates entry if it does not exist.
     *
     * @param incert The certificate to be stored.
     * @param username username of end entity owning the certificate.*
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param status Status of the certificate (from CertificateData).
     * @param type Type of certificate (from SecConst).
     *
     * @return true if storage was successful.
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type) {

        int ldapVersion  = LDAPConnection.LDAP_V3;
        LDAPConnection lc = new LDAPConnection();

        String dn = null;
        try {
            // Extract the users DN from the cert.
            dn = CertTools.getSubjectDN((X509Certificate)incert);
        } catch (Exception e) {
            error("Error decoding input certificate: ",e);
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Error decoding input certificate.");
            }catch(RemoteException re){}
            return false;
        }

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
                DEROctetString asn1 = (DEROctetString)new DERInputStream(bIn).readObject();
                ByteArrayInputStream bIn1 = new ByteArrayInputStream(asn1.getOctets());
                ASN1Sequence san = (ASN1Sequence)new DERInputStream(bIn1).readObject();
                for (int i=0;i<san.size();i++) {
                    DERTaggedObject gn = (DERTaggedObject)san.getObjectAt(i);
                    if (gn.getTagNo() == 1) {
                        // This is rfc822Name!
                        DERIA5String str;
                        if (gn.getObject() instanceof DERIA5String)
                            str = (DERIA5String)gn.getObject();
                        else
                            str = new DERIA5String(((DEROctetString)gn.getObject()).getOctets());
                        email = str.getString();
                    }
                }
            } catch (IOException e) {
                error("IOException when getting subjectAltNames extension.");
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"IOException when getting subjectAltNames extension.");
                }catch(RemoteException re){}
            }
        }

        if (checkContainerName(dn) == false) {
            info("DN not part of containername, aborting store operation.");
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"DN not part of containername, aborting store operation.");
            }catch(RemoteException re){}
            return false;
        }

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = null;
        try {
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );
            // try to read the old object
            oldEntry = lc.read(dn);
            // disconnect with the server
            lc.disconnect();
        } catch( LDAPException e ) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                debug("No old entry exist for '"+dn+"'.");
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,"No old entry exist for '"+dn+"'.");
                }catch(RemoteException re){}
            } else {
                error( "Error binding to and reading from LDAP server: ", e);
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Error binding to and reading from LDAP server.");
                }catch(RemoteException re){}
                return false;
            }
        }

        LDAPEntry newEntry = null;
        LDAPModificationSet modSet = null;
        LDAPAttributeSet attributeSet = null;
        String attribute = null, objectclass = null;
        if ( type == SecConst.CERTTYPE_ENDENTITY ) {
            debug("Publishing end user certificate to "+ldapHost);
            if (oldEntry != null) {
                // TODO: Are we the correct type objectclass?
                modSet = getModificationSet(oldEntry, dn, true);
            } else
                objectclass = userObjectclass;
                attributeSet = getAttributeSet(userObjectclass, dn, true);
            if (email != null) {
                LDAPAttribute mailAttr = new LDAPAttribute( "mail", email );
                if (oldEntry != null)
                    modSet.add(LDAPModification.REPLACE, mailAttr);
                else
                    attributeSet.add( mailAttr );
            }
            try {
                attribute = userCertAttribute;
                LDAPAttribute certAttr = new LDAPAttribute( userCertAttribute, incert.getEncoded() );
                if (oldEntry != null)
                    modSet.add(LDAPModification.REPLACE, certAttr);
                else
                    attributeSet.add( certAttr );
            } catch (CertificateEncodingException e) {
                error("Error encoding certificate when storing in LDAP: ",e);
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Error encoding certificate when storing in LDAP.");
                }catch(RemoteException re){}
                return false;
            }
        } else if (type == SecConst.CERTTYPE_CA  || type == SecConst.CERTTYPE_ROOTCA) {
            debug("Publishing CA certificate to "+ldapHost);
            if (oldEntry != null)
                modSet = getModificationSet(oldEntry, dn, false);
            else
                objectclass = cAObjectclass;
                attributeSet = getAttributeSet(cAObjectclass, dn, false);
            try {
                attribute = cACertAttribute;
                LDAPAttribute certAttr = new LDAPAttribute( cACertAttribute, incert.getEncoded() );
                if (oldEntry != null)
                    modSet.add(LDAPModification.REPLACE, certAttr);
                else {
                    attributeSet.add( certAttr );
                    // Also create using the crlattribute, it may be required
                    LDAPAttribute crlAttr = new LDAPAttribute( cRLAttribute, "" );
                    attributeSet.add( crlAttr );
                    debug("Added (fake) attribute for CRL.");
                }
            } catch (CertificateEncodingException e) {
                error("Error encoding certificate when storing in LDAP: ",e);
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Error encoding certificate when storing in LDAP.");
                }catch(RemoteException re){}
                return false;
            }
        } else {
            info("Certificate of type '"+type+"' will not be published.");
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Certificate of type '"+type+"' will not be published.");
            }catch(RemoteException re){}
            return false;
        }
        try {
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );
            // Add or modify the entry
            if (oldEntry != null) {
                lc.modify(dn, modSet);
                debug( "\nModified object: " + dn + " successfully." );
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,"Modified object: " + dn + " successfully in LDAP.");
                }catch(RemoteException re){}
            } else {
                if (oldEntry == null)
                    newEntry = new LDAPEntry( dn, attributeSet );
                lc.add( newEntry );
                debug( "\nAdded object: " + dn + " successfully." );
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,"Added object: " + dn + " successfully in LDAP.");
                }catch(RemoteException re){}
            }
            // disconnect with the server
            lc.disconnect();
        }
        catch( LDAPException e ) {
            error( "Error storing certificate ("+attribute+") in LDAP ("+objectclass+"): ", e);
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"Error storing certificate ("+attribute+") in LDAP ("+objectclass+").");
            }catch(RemoteException re){}
            return false;
        }

        return true;
    } // storeCertificate

    /**
     * Revokes a certificate (already revoked by the CA), the Publisher decides what to do, if anything.
     *
     * @param cert The DER coded Certificate that has been revoked.
     * @throws EJBException if a communication or other error occurs.
     */
     public void revokeCertificate(Admin admin, Certificate cert, int reason) {
         // TODO: remove revoked certificate from LDAP
     } //revokeCertificate
     
    /**
     * Published a CRL to LDAP. Creates CA entry if it does not exist.
     *
     * @param incrl The DER coded CRL to be stored.
     * @param chainfp Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     *
     * @return true if storage was successful.
     * @throws EJBException if a communication or other error occurs.
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) {

        int ldapVersion  = LDAPConnection.LDAP_V3;
        LDAPConnection lc = new LDAPConnection();

        X509CRL crl = null;
        String dn = null;
        try {
            crl = CertTools.getCRLfromByteArray(incrl);
            // Extract the users DN from the crl.
            dn = CertTools.getIssuerDN(crl);
        } catch (Exception e) {
            error("Error decoding input CRL: ",e);
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"Error decoding input CRL.");
            }catch(RemoteException re){}
            return false;
        }

        if (checkContainerName(dn) == false) {
            info("DN not part of containername, aborting store operation.");
            try{
              logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"DN not part of containername, aborting store operation.");
            }catch(RemoteException re){}
            return false;
        }

        // Check if the entry is already present, we will update it with the new certificate.
        LDAPEntry oldEntry = null;
        try {
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );
            // try to read the old object
            oldEntry = lc.read(dn);
            // disconnect with the server
            lc.disconnect();
        } catch( LDAPException e ) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT) {
                debug("No old entry exist for '"+dn+"'.");
            } else {
                error( "Error binding to and reading from LDAP server: ", e);
               try{
                 logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"Error binding to and reading from LDAP server.");
               }catch(RemoteException re){}
                return false;
            }
        }
        LDAPEntry newEntry = null;
        LDAPModificationSet modSet = null;

        LDAPAttributeSet attributeSet = null;
        if (oldEntry != null)
            modSet = getModificationSet(oldEntry, dn, false);
        else
            attributeSet = getAttributeSet(cAObjectclass, dn, false);
        try {
            LDAPAttribute crlAttr = new LDAPAttribute( cRLAttribute, crl.getEncoded() );
            if (oldEntry != null)
                modSet.add(LDAPModification.REPLACE, crlAttr);
            else
                attributeSet.add( crlAttr );
        } catch (CRLException e) {
            error("Error encoding CRL when storing in LDAP: ",e);
            try{
               logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"Error encoding CRL when storing in LDAP.");
            }catch(RemoteException re){}
            return false;
        }
        if (oldEntry == null)
            newEntry = new LDAPEntry( dn, attributeSet );
        try {
            // connect to the server
            lc.connect( ldapHost, ldapPort );
            // authenticate to the server
            lc.bind( ldapVersion, loginDN, loginPassword );
            // Add or modify the entry
            if (oldEntry != null) {
                lc.modify(dn, modSet);
                debug( "\nModified object: " + dn + " successfully." );
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_STORECRL,"Modified object: " + dn + " successfully in LDAP.");
                }catch(RemoteException re){}
            } else {
                lc.add( newEntry );
                debug( "\nAdded object: " + dn + " successfully." );
                try{
                  logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_STORECRL,"Added object: " + dn + " successfully in LDAP.");
                }catch(RemoteException re){}
            }
            // disconnect with the server
            lc.disconnect();
        }
        catch( LDAPException e ) {
            error( "Error storing CRL ("+cRLAttribute+") in LDAP ("+cAObjectclass+"): ", e);
            try{
               logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"Error storing CRL ("+cRLAttribute+") in LDAP ("+cAObjectclass+").");
            }catch(RemoteException re){}
            return false;
        }

        return true;
    } // storeCRL     

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

    /** Creates an LDAPAttributeSet.
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @return LDAPAtributeSet created...
     */
    private LDAPAttributeSet getAttributeSet(String objectclass, String dn, boolean extra)
    {
        LDAPAttributeSet attributeSet = new LDAPAttributeSet();

        /* To Add an entry to the directory,
         *   -- Create the attributes of the entry and add them to an attribute set
         *   -- Specify the DN of the entry to be created
         *   -- Create an LDAPEntry object with the DN and the attribute set
         *   -- Call the LDAPConnection add method to add it to the directory
         */
        attributeSet.add( new LDAPAttribute( "objectclass", objectclass ) );
        if (extra) {
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
        }
        return attributeSet;
    } // getAttributeSet

    /** Creates an LDAPModificationSet.
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the modificationset.
     * @return LDAPModificationSet created...
     */
    private LDAPModificationSet getModificationSet(LDAPEntry oldEntry, String dn, boolean extra)
    {
        LDAPModificationSet modSet = new LDAPModificationSet();

        if (extra) {
            String cn = CertTools.getPartFromDN(dn,"CN");
            if (cn!=null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute( "cn", cn));
            }
            String sn = CertTools.getPartFromDN(dn,"SN");
            if (sn!=null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute( "sn", sn ) );
            }
            String l = CertTools.getPartFromDN(dn,"L");
            if (l!=null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute( "l", l ) );
            }
            String st = CertTools.getPartFromDN(dn,"ST");
            if (st!=null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute( "st", st ) );
            }
            String ou = CertTools.getPartFromDN(dn,"OU");
            if (ou!=null) {
                modSet.add(LDAPModification.REPLACE, new LDAPAttribute( "ou", ou ) );
            }
        }
        return modSet;
    } // getModificationSet
}
