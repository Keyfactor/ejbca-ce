package se.anatom.ejbca.authorization;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import se.anatom.ejbca.log.Admin;


/**
 *
 * @version $Id: IAuthorizationSessionRemote.java,v 1.3 2004-02-19 12:16:49 herrvendil Exp $
 */
public interface IAuthorizationSessionRemote extends javax.ejb.EJBObject {
    

    // Methods used with AvailableAccessRulesData Entity beans.
    /**
     * Constant indicating minimum time between updates. In milliseconds
     */
    public static final long MINTIMEBETWEENUPDATES = 60000*1;
    
    /**
     * Method to initialize authorization bean, must be called directly after creation of bean.
     */
    public void initialize(Admin admin, int caid) throws RemoteException, AdminGroupExistsException;

     /**
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admin the administrator about to be authorized, see se.anatom.ejbca.log.Admin class.
     * @param resource the resource to check authorization for.
     */
    public boolean isAuthorized(Admin admin, String resource) throws  AuthorizationDeniedException, RemoteException;

     /**
     * Method to check if a user is authorized to a certain resource without performing any logging.
     *
     * @param admin the administrator about to be authorized, see se.anatom.ejbca.log.Admin class.
     * @param resource the resource to check authorization for. 
     */
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException, RemoteException;

	/**
	 * Method to check if a group is authorized to a resource. 
	 */
	public boolean isGroupAuthorized(Admin admin, int admingrouppk, String resource) throws AuthorizationDeniedException, RemoteException;

	/**
	 * Method to check if a group is authorized to a resource without any logging. 
	 */
	public boolean isGroupAuthorizedNoLog(Admin admin, int admingrouppk, String resource) throws AuthorizationDeniedException, RemoteException;


	/**
	 * Method to check if an administrator exists in the specified admingroup. 
	 */
	public boolean existsAdministratorInGroup(Admin admin, int admingrouppk) throws RemoteException;

    /**
     * Method to validate and check revokation status of a users certificate.
     *
     * @param certificate the users X509Certificate.
     *
     */

    public void authenticate(X509Certificate certificate) throws AuthenticationFailedException, RemoteException;

   /**
    * Method to add an admingroup.
    *
    * @param admingroupname name of new admingroup, have to be unique.
    * @throws AdminGroupExistsException if admingroup already exists.
    */
    public void addAdminGroup(Admin admin, String admingroupname, int caid) throws AdminGroupExistsException , RemoteException;

    /**
     * Method to remove a admingroup.
     */
    public void removeAdminGroup(Admin admin, String admingroupname, int caid) throws RemoteException;

    /**
     * Metod to rename a admingroup
     *
     * @throws AdminGroupExistsException if admingroup already exists.
     */
    public void renameAdminGroup(Admin admin, String oldname, int caid, String newname) throws AdminGroupExistsException , RemoteException;
    

    /**
     * Method to get a reference to a admingroup.
     */

    public AdminGroup getAdminGroup(Admin admin, String admingroupname, int caid) throws RemoteException;

         
    /**
     * Returns a Collection of AdminGroups the administrator is authorized to. 
     */
    
     public Collection getAuthorizedAdminGroupNames(Admin admin) throws RemoteException;

     /**
     * Adds a Collection of AccessRule to an an admin group.
     *
     */
    public void addAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules) throws RemoteException;


     /**
     * Removes a Collection of (Sting) containing accessrules to remove from admin group.
     *
     */
    public void removeAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules) throws RemoteException;

    /**
     * Replaces a groups accessrules with a new set of rules
     *
     */
    public void replaceAccessRules(Admin admin, String admingroupname, int caid, Collection accessrules) throws RemoteException;    
    
     /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values if they already exists.
     *
     */

    public void addAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities) throws RemoteException;


     /**
     * Removes a Collection of AdminEntity from the administrator group.
     *
     */
    public void removeAdminEntities(Admin admin, String admingroupname, int caid, Collection adminentities) throws RemoteException;    
    
    /**
     * Method used to collect an administrators available access rules based on which rule
     * he himself is authorized to.
     *
     * @param admin is the administrator calling the method.
     * @return a Collection of String containing available accessrules.
     */
    
   public Collection getAuthorizedAvailableAccessRules(Admin admin) throws RemoteException;
   
    /**
     * Method used to return an Collection of Integers indicating which CAids a administrator
     * is authorized to access.
     */       
    public Collection getAuthorizedCAIds(Admin admin) throws RemoteException;


    /**
     * Method used to return an Collection of Integers indicating which end entity profiles
     * the administrator is authorized to view.
     *
     * @param admin, the administrator 
     * @rapriviledge should be one of the end entity profile authorization constans defined in AvailableAccessRules.
     */ 
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge) throws RemoteException;
    
    /**
     * Method to check if an end entity profile exists in any end entity profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */

    public boolean existsEndEntityProfileInRules(Admin admin, int profileid) throws RemoteException;

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid desyncronization of CA rules when ca is removed
     * @param caid the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     */

    public boolean existsCAInRules(Admin admin, int profileid) throws RemoteException;
    
   
}

