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
 
package se.anatom.ejbca.authorization;

import java.security.cert.X509Certificate;
import java.util.Collection;

import se.anatom.ejbca.log.Admin;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see IAuthorizationSessionRemote for docs.
 *
 * @version $Id: IAuthorizationSessionLocal .java
 * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
 */

public interface IAuthorizationSessionLocal extends javax.ejb.EJBLocalObject
{
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public static final long MINTIMEBETWEENUPDATES = IAuthorizationSessionRemote.MINTIMEBETWEENUPDATES;

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void initialize(Admin admin, int caid) throws  AdminGroupExistsException;
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public boolean isAuthorized(Admin admin, String resource) throws  AuthorizationDeniedException;

     /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException;

	/**
	 * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
	 */
	public boolean isGroupAuthorized(Admin admin, int admingrouppk, String resource) throws AuthorizationDeniedException;

	/**
	 * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
	 */
	public boolean isGroupAuthorizedNoLog(Admin admin, int admingrouppk, String resource) throws AuthorizationDeniedException;

	/**
	 * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
	 */
	public boolean existsAdministratorInGroup(Admin admin, int admingrouppk);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException;

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void addAdminGroup(Admin admin, String admingroupname, int caid) throws AdminGroupExistsException;

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void removeAdminGroup(Admin admin, String admingroupname, int caid);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void renameAdminGroup(Admin admin, String oldname, int caid, String newname) throws AdminGroupExistsException;
    

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public AdminGroup getAdminGroup(Admin admin, String admingroupname, int caid);

         
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public Collection getAuthorizedAdminGroupNames(Admin admin);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void addAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules);


    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void removeAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void replaceAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules);
    
    
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void addAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities);


    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public void removeAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities);


    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public Collection getAuthorizedAvailableAccessRules(Admin admin);
    
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public Collection getAuthorizedCAIds(Admin admin);
    
    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */    
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid);

    /**
     * @see se.anatom.ejbca.authorization.IAuthorizationSessionRemote
     */
    public boolean existsCAInRules(Admin admin, int profileid);
    
   

}

