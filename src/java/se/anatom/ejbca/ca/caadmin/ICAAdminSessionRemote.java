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
 

package se.anatom.ejbca.ca.caadmin;

import java.rmi.RemoteException;
import java.security.cert.CertPathValidatorException;
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
 * @version $Id: ICAAdminSessionRemote.java,v 1.5 2004-04-16 07:38:58 anatom Exp $
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
  public Collection getAvailableCAs(Admin admin) throws RemoteException;
    
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public IResponseMessage processRequest(Admin admin, CAInfo cainfo, IRequestMessage requestmessage) throws CAExistsException, CADoesntExistsException, AuthorizationDeniedException, RemoteException;

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void renewCA(Admin admin, int caid, IResponseMessage responcemessage) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, RemoteException;

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

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public boolean exitsPublisherInCAs(Admin admin, int publisherid) throws RemoteException;
    
}

