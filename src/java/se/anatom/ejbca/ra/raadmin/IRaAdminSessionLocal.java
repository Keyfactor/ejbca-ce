
package se.anatom.ejbca.ra.raadmin;


import java.math.BigInteger;
import java.util.Collection;
import java.util.TreeMap;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.UserPreference;
import se.anatom.ejbca.ra.raadmin.Profile;


/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IRaAdminSessionLocal.java,v 1.4 2002-07-22 10:38:48 anatom Exp $
 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
 */

public interface IRaAdminSessionLocal extends javax.ejb.EJBLocalObject

{

    public UserPreference getUserPreference(BigInteger serialnumber);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean addUserPreference(BigInteger serialnumber, UserPreference userpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean changeUserPreference(BigInteger serialnumber, UserPreference userpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean existsUserPreference(BigInteger serialnumber);



    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean addProfile(String profilename, Profile profile);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean cloneProfile(String originalprofilename, String newprofilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public void removeProfile(String profilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean renameProfile(String oldprofilename, String newprofilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */

    public boolean changeProfile(String profilename, Profile profile);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public Collection getProfileNames();
     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public TreeMap getProfiles();

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public Profile getProfile(String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public Profile getProfile(int id);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getNumberOfProfiles();

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getProfileId(String profilename);

     /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public String getProfileName(int id);

}

