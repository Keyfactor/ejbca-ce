package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

import java.math.BigInteger;

import java.util.Collection;
import java.util.TreeMap;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: IRaAdminSessionLocal.java,v 1.10 2003-06-26 11:43:25 anatom Exp $
 *
 * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
 */
public interface IRaAdminSessionLocal extends javax.ejb.EJBLocalObject {
    public static final String EMPTY_ENDENTITYPROFILE = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILE;
    public static final int EMPTY_ENDENTITYPROFILEID = LocalRaAdminSessionBean.EMPTY_ENDENTITYPROFILEID;

    /**
     * DOCUMENT ME!
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference(Admin admin, BigInteger serialnumber);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean addAdminPreference(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean changeAdminPreference(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean changeAdminPreferenceNoLog(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean existsAdminPreference(Admin admin, BigInteger serialnumber);

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
    public boolean addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean cloneEndEntityProfile(Admin admin, String originalprofilename,
        String newprofilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public void removeEndEntityProfile(Admin admin, String profilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public boolean changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public Collection getEndEntityProfileNames(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public TreeMap getEndEntityProfiles(Admin admin);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, int id);

    /**
     * @see se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote
     */
    public int getNumberOfEndEntityProfiles(Admin admin);

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
}
