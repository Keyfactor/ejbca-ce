
package se.anatom.ejbca.ra.raadmin;


import java.math.BigInteger;
import java.util.Collection;
import java.util.TreeMap;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IRaAdminSessionLocal.java,v 1.6 2002-10-24 20:09:29 herrvendil Exp $
 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
 */

public interface IRaAdminSessionLocal extends javax.ejb.EJBLocalObject

{

    public final static String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE;
    public final static int EMPTY_ENDENTITYPROFILEID  = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILEID;    
    
    public AdminPreference getAdminPreference(BigInteger serialnumber);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean addAdminPreference(BigInteger serialnumber, AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean changeAdminPreference(BigInteger serialnumber, AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean existsAdminPreference(BigInteger serialnumber);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */  
    
    public AdminPreference getDefaultAdminPreference();
    
    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public void saveDefaultAdminPreference(AdminPreference defaultadminpreference);   

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean addEndEntityProfile(String profilename, EndEntityProfile profile);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean cloneEndEntityProfile(String originalprofilename, String newprofilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void removeEndEntityProfile(String profilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean renameEndEntityProfile(String oldprofilename, String newprofilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean changeEndEntityProfile(String profilename, EndEntityProfile profile);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public Collection getEndEntityProfileNames();
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public TreeMap getEndEntityProfiles();

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(int id);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getNumberOfEndEntityProfiles();

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getEndEntityProfileId(String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public String getEndEntityProfileName(int id);
    
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    
    public boolean existsCertificateProfileInEndEntityProfiles(int certificateprofileid);    

}

