package se.anatom.ejbca.ra.raadmin;

import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;

/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IRaAdminSessionLocal.java,v 1.14 2004-01-31 14:24:59 herrvendil Exp $
 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
 */

public interface IRaAdminSessionLocal extends javax.ejb.EJBLocalObject

{

    public final static String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILENAME;
    public final static int EMPTY_ENDENTITYPROFILEID  = SecConst.EMPTY_ENDENTITYPROFILE;
    
    public AdminPreference getAdminPreference(Admin admin, String certificatefingerprint);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean addAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean changeAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public boolean changeAdminPreferenceNoLog(Admin admin, String certificatefingerprint, AdminPreference adminpreference);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean existsAdminPreference(Admin admin, String certificatefingerprint);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */  
    
    public AdminPreference getDefaultAdminPreference(Admin admin);
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference);   

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public void addEndEntityProfile(Admin admin, int profileid, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException;

	/**
	 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
	 */
    public void addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException;

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void cloneEndEntityProfile(Admin admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException;

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void removeEndEntityProfile(Admin admin, String profilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException;

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */    
    public Collection getAuthorizedEndEntityProfileIds(Admin admin);

    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public HashMap getEndEntityProfileIdToNameMap(Admin admin);    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, int id);
    
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getEndEntityProfileId(Admin admin, String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public String getEndEntityProfileName(Admin admin, int id);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid);    

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public boolean existsCAInEndEntityProfiles(Admin admin, int caid);      

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globalconfiguration);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public GlobalConfiguration loadGlobalConfiguration(Admin admin);    

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public void initGlobalConfigurationBaseURL(Admin admin, String computername, String applicationpath);
    
}

