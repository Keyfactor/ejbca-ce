
package se.anatom.ejbca.ca.caadmin;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;

/** Remote interface of CAAdmin session bean for EJB. Manages CAs
 *
 * @version $Id: ICAAdminSessionRemote.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
 */
public interface ICAAdminSessionRemote extends javax.ejb.EJBObject {
 


  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void createCA(Admin admin, CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException, RemoteException;
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void editCA(Admin admin, CAInfo cainfo) throws AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void removeCA(Admin admin, int caid) throws AuthorizationDeniedException, RemoteException; 

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void renameCA(Admin admin, String oldname, String newname) throws CAExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public CAInfo getCAInfo(Admin admin, String name) throws RemoteException;

   /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public CAInfo getCAInfo(Admin admin, int caid) throws RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public HashMap getCAIdToNameMap(Admin admin) throws RemoteException;
  
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public Collection processRequest(Admin admin, String username, String password, IRequestMessage requestmessage) throws CADoesntExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void renewCA(Admin admin, int caid, IResponseMessage responcemessage) throws CADoesntExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void revokeCA(Admin admin, int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException, RemoteException;  
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void upgradeFromOldCAKeyStore(Admin admin, String caname, byte[] p12file, char[] keystorepass,
                                char[] privkeypass, String privatekeyalias) throws RemoteException;
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public Collection getAllCACertificates(Admin admin) throws RemoteException;
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public boolean exitsCertificateProfileInCAs(Admin admin, int certificateprofileid) throws RemoteException;
    
}

