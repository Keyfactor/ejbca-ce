
package se.anatom.ejbca.ca.caadmin;

import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;

/** Local interface of CAAdmin sessio bean for EJB. Manages CAs
 *
 * @version $Id: ICAAdminSessionLocal.java,v 1.2 2003-10-03 14:34:20 herrvendil Exp $
 */
public interface ICAAdminSessionLocal extends javax.ejb.EJBLocalObject {
 


  /**
   * Method used to create a new CA.
   *
   * The cainfo parameter should at least contain the following information.
   *   SubjectDN
   *   Name (if null then is subjectDN used).
   *   Validity
   *   a CATokenInfo
   *   Description (optional)
   *   Status (SecConst.CA_ACTIVE or SecConst.CA_WAITING_CERTIFICATE_RESPONSE)
   *   SignedBy (CAInfo.SELFSIGNED, CAInfo.SIGNEDBYEXTERNALCA or CAId of internal CA)    
   *
   *  For other optional values see:
   *  @see se.anatom.ejbca.ca.caadmin.CAInfo
   *  @see se.anatom.ejbca.ca.caadmin.X509CAInfo
   */
  public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException;
  
  /**
   * Method used to edit the data of a CA. 
   * 
   * Not all of the CAs data can be edited after the creation, therefore will only
   * the values from CAInfo that is possible be uppdated. 
   *
   * 
   *  For values see:
   *  @see se.anatom.ejbca.ca.caadmin.CAInfo
   *  @see se.anatom.ejbca.ca.caadmin.X509CAInfo
   */
  public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException;

  /**
   * Method used to remove a CA from the system. 
   *
   * First there is a check that the CA isn't used by any EndEntity, Profile or AccessRule
   * before it is removed. 
   * 
   * Should be used with care. If any certificate has been created with the CA use revokeCA instead
   * and don't remove it.
   */
  
  public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException; 

  /**
   * Renames the name of CA used in administrators web interface.
   * 
   * This name doesn't have to be the same as SubjectDN and is only used for reference.
   */
  
  public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException;

  /**
   * Returns a value object containing nonsensitive information about a CA give it's name.
   */
  public CAInfo getCAInfo(Admin admin, String name);

  /**
   * Returns a value object containing nonsensitive information about a CA give it's CAId.
   */  
  public CAInfo getCAInfo(Admin admin, int caid);

   /**
   * Returns a HashMap containing mappings of caid to CA name of all CAs in the system.
   */  
  public HashMap getCAIdToNameMap(Admin admin);
  
  
  /**
   *  Creates a certificate request that should be sent to External Root CA for process before
   *  activation of CA.
   *
   *  @rootcertificates A Collection of rootcertificates.
   *  @setstatustowaiting should be set true when creating new CAs and false for renewing old CAs
   */
  public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   *  Receives a certificate response from an external CA and sets the newly created CAs status
   *  to active.
   *
   */  
  public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   *  Processes a Certificate Request from an external CA. 
   *  The external CA should first have been added to the user database.
   *  As much data from the database will be used and not from the certificaterequest. ??
   *
   */  
  public Collection processRequest(Admin admin, String username, String password, IRequestMessage requestmessage) throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   *  Renews a existing CA certificate using the same keys as before. Data  about new CA is taken
   *  from database.
   * 
   *  @param certificateresponce should be set with new certificatechain if CA is signed by external
   *         RootCA, otherwise use the null value. 
   *
   */  
  public void renewCA(Admin admin, int caid, IResponseMessage responcemessage) throws CADoesntExistsException, AuthorizationDeniedException;

  /**
   *  Method that revokes the CA. After this is all certificates created by this CA
   *  revoked and a final CRL is created.
   *
   *  @param reason one of RevokedCertInfo.REVOKATION_REASON values.
   *
   */
  public void revokeCA(Admin admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException;  
  
  /**
   * Method that should be used when upgrading from a older version of EJBCA. i.e. >3.0
   *
   * @param a byte array of old server p12 file.
   * @param keystorepass used to unlock the keystore.
   * @parma privkeypass used to unlock the private key.
   */
  public void upgradeFromOldCAKeyStore(Admin admin, String caname, byte[] p12file, char[] keystorepass,
                                char[] privkeypass, String privatekeyalias);
  
  /**
   *  Method returning a Collection of Certificate of all CA certificates known to the system.
   */
  public Collection getAllCACertificates(Admin admin);
  
  /**
   *  Method used to check if certificate profile id exists in any CA.
   */    
  public boolean exitsCertificateProfileInCAs(Admin admin, int certificateprofileid);
    
}

