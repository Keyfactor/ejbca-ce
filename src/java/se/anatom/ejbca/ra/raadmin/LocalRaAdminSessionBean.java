package se.anatom.ejbca.ra.raadmin;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;

import java.math.BigInteger;

import java.rmi.*;

import java.sql.*;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.TreeMap;
import java.util.Vector;

import javax.ejb.*;

import javax.naming.*;

import javax.sql.DataSource;


/**
 * Stores data used by web server clients. Uses JNDI name for datasource as defined in env
 * 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalRaAdminSessionBean.java,v 1.27 2003-07-23 09:40:16 anatom Exp $
 */
public class LocalRaAdminSessionBean extends BaseSessionBean {
    private static Logger log = Logger.getLogger(LocalRaAdminSessionBean.class);

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of  AdminPreferences entity bean */
    private AdminPreferencesDataLocalHome adminpreferenceshome = null;

    /** The home interface of  EndEntityProfileData entity bean */
    private EndEntityProfileDataLocalHome profiledatahome = null;

    /** The remote interface of  log session bean */
    private ILogSessionRemote logsession = null;
    public static final String EMPTY_ENDENTITYPROFILE = "EMPTY";
    public static final int EMPTY_ENDENTITYPROFILEID = SecConst.EMPTY_ENDENTITYPROFILE;
    private static final String DEFAULTUSERPREFERENCE = "default";

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");

        try {
            dataSource = (String) lookup("java:comp/env/DataSource", java.lang.String.class);
            debug("DataSource=" + dataSource);

            adminpreferenceshome = (AdminPreferencesDataLocalHome) lookup("java:comp/env/ejb/AdminPreferencesDataLocal",
                    AdminPreferencesDataLocalHome.class);
            profiledatahome = (EndEntityProfileDataLocalHome) lookup("java:comp/env/ejb/EndEntityProfileDataLocal",
                    EndEntityProfileDataLocalHome.class);

            ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",
                    ILogSessionHome.class);
            logsession = logsessionhome.create();
            debug("<ejbCreate()");

            try {
                adminpreferenceshome.findByPrimaryKey(DEFAULTUSERPREFERENCE);
            } catch (FinderException e) {
                adminpreferenceshome.create(DEFAULTUSERPREFERENCE, new AdminPreference());
            }

            try {
                profiledatahome.findByProfileName(EMPTY_ENDENTITYPROFILE);
            } catch (FinderException e) {
                profiledatahome.create(new Integer(EMPTY_ENDENTITYPROFILEID),
                    EMPTY_ENDENTITYPROFILE, new EndEntityProfile(true));
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Gets connection to Datasource used for manual SQL searches
     *
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource) getInitialContext().lookup(dataSource);

        return ds.getConnection();
    }
     //getConnection

    /**
     * Finds the admin preference belonging to a certificate serialnumber. Returns null if admin
     * doesn't exists.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public AdminPreference getAdminPreference(Admin admin, BigInteger serialnumber) {
        debug(">getAdminPreference()");

        AdminPreference ret = null;

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(serialnumber.toString());
            ret = apdata.getAdminPreference();
        } catch (javax.ejb.FinderException fe) {
            // Create new configuration
            ret = null;
        } catch (Exception e) {
            throw new EJBException(e);
        }

        debug("<getAdminPreference()");

        return ret;
    }
     // getAdminPreference

    /**
     * Adds a admin preference to the database. Returns false if admin already exists.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean addAdminPreference(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference) {
        debug(">addAdminPreference(serial : " + serialnumber + ")");

        boolean ret = false;

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.create(serialnumber.toString(),
                    adminpreference);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,
                "Administrator preference added.");
            ret = true;
        } catch (Exception e) {
            error("Error adding admin preference: ", e);
            ret = false;
            try {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,
                    "Trying to add preference for administrator that already exists.");
            } catch (RemoteException re) {
            }
        }

        debug("<addAdminPreference()");

        return ret;
    }
     // addAdminPreference

    /**
     * Changes the admin preference in the database. Returns false if admin doesn't exists.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean changeAdminPreference(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference) {
        debug(">changeAdminPreference(serial : " + serialnumber + ")");

        return updateAdminPreference(admin, serialnumber, adminpreference, true);
    }
     // changeAdminPreference

    /**
     * Changes the admin preference in the database. Returns false if admin doesn't exists.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean changeAdminPreferenceNoLog(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference) {
        debug(">changeAdminPreferenceNoLog(serial : " + serialnumber + ")");

        return updateAdminPreference(admin, serialnumber, adminpreference, false);
    }
     // changeAdminPreference

    /**
     * Checks if a admin preference exists in the database.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean existsAdminPreference(Admin admin, BigInteger serialnumber) {
        debug(">existsAdminPreference(serial : " + serialnumber + ")");

        boolean ret = false;

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(serialnumber.toString());
            ret = true;
        } catch (javax.ejb.FinderException fe) {
            ret = false;
        } catch (Exception e) {
            throw new EJBException(e);
        }

        debug("<existsAdminPreference()");

        return ret;
    }
     // existsAdminPreference

    /**
     * Function that returns the default admin preference.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public AdminPreference getDefaultAdminPreference(Admin admin) {
        debug(">getDefaultAdminPreference()");

        AdminPreference ret = null;

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(DEFAULTUSERPREFERENCE);
            ret = apdata.getAdminPreference();
        } catch (javax.ejb.FinderException fe) {
            // Create new configuration
            ret = null;
        } catch (Exception e) {
            throw new EJBException(e);
        }

        debug("<getDefaultAdminPreference()");

        return ret;
    }
     // getDefaultPreference()

    /**
     * Function that saves the default admin preference.
     *
     * @param admin DOCUMENT ME!
     * @param defaultadminpreference DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference) {
        debug(">saveDefaultAdminPreference()");

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(DEFAULTUSERPREFERENCE);
            apdata.setAdminPreference(defaultadminpreference);
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,
                "Default administrator preference changed.");
        } catch (Exception e) {
            error("Error saving default admin preference: ", e);
            try {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED,
                    "Error saving default administrator preference.");
            } catch (RemoteException re) {
                throw new EJBException(e);
            }

            throw new EJBException(e);
        }

        debug("<saveDefaultAdminPreference()");
    }
     // ssaveDefaultAdminPreference

    /**
     * Adds a profile to the database.
     *
     * @param admin DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) {
        boolean returnval = false;

        try {
            profiledatahome.findByProfileName(profilename);
        } catch (FinderException e) {
            try {
                profiledatahome.create(findFreeEndEntityProfileId(), profilename, profile);
                returnval = true;
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ENDENTITYPROFILE,
                    "End entity profile " + profilename + " added.");
            } catch (Exception f) {
                error("Error adding end entity profile: ", e);
                try {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_ENDENTITYPROFILE,
                        "Error adding end entity profile " + profilename);
                } catch (RemoteException re) {
                }
            }
        }

        return returnval;
    }
     // addEndEntityProfile

    /**
     * Adds a end entity profile to a group with the same content as the original profile.
     *
     * @param admin DOCUMENT ME!
     * @param originalprofilename DOCUMENT ME!
     * @param newprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean cloneEndEntityProfile(Admin admin, String originalprofilename,
        String newprofilename) {
        EndEntityProfile profile = null;
        boolean returnval = false;

        try {
            EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(originalprofilename);
            profile = (EndEntityProfile) pdl.getProfile().clone();

            returnval = addEndEntityProfile(admin, newprofilename, profile);

            if (returnval) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ENDENTITYPROFILE,
                    "New end entity profile " + newprofilename + " used profile " +
                    originalprofilename + " as template.");
            } else {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ENDENTITYPROFILE,
                    "Error adding end entity profile " + newprofilename + " using profile " +
                    originalprofilename + " as template.");
            }
        } catch (Exception e) {
            error("Error cloing end entity profile: ", e);
        }

        return returnval;
    }
     // cloneEndEntityProfile

    /**
     * Removes an end entity profile from the database.
     *
     * @param admin DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeEndEntityProfile(Admin admin, String profilename) {
        try {
            EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);
            pdl.remove();
            logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_ENDENTITYPROFILE,
                "End entity profile " + profilename + " removed.");
        } catch (Exception e) {
            error("Error removing end entity profile: ", e);
            try {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ENDENTITYPROFILE,
                    "Error removing end entity profile " + profilename + ".");
            } catch (RemoteException re) {
            }
        }
    }
     // removeEndEntityProfile

    /**
     * Renames a end entity profile
     *
     * @param admin DOCUMENT ME!
     * @param oldprofilename DOCUMENT ME!
     * @param newprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) {
        boolean returnvalue = false;

        try {
            profiledatahome.findByProfileName(newprofilename);
        } catch (FinderException e) {
            try {
                EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(oldprofilename);
                pdl.setProfileName(newprofilename);
                returnvalue = true;
            } catch (FinderException f) {
            }
        }

        try {
            if (returnvalue) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ENDENTITYPROFILE,
                    "End entity profile " + oldprofilename + " renamed to " + newprofilename + ".");
            } else {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ENDENTITYPROFILE,
                    " Error renaming end entity profile " + oldprofilename + " to " +
                    newprofilename + ".");
            }
        } catch (RemoteException e) {
        }

        return returnvalue;
    }
     // remameProfile

    /**
     * Updates profile data
     *
     * @param admin DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) {
        boolean returnvalue = false;

        try {
            EndEntityProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);
            pdl.setProfile(profile);
            returnvalue = true;
        } catch (FinderException e) {
        }

        try {
            if (returnvalue) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ENDENTITYPROFILE,
                    "End entity profile " + profilename + " edited.");
            }
            else {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_ENDENTITYPROFILE,
                    "Error editing end entity profile " + profilename + ".");
            }
        } catch (RemoteException e) {
        }

        return returnvalue;
    }
     // changeEndEntityProfile

    /**
     * Retrives profile names sorted.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection getEndEntityProfileNames(Admin admin) {
        Vector returnval = new Vector();
        Collection result = null;

        try {
            result = profiledatahome.findAll();

            if (result.size() > 0) {
                Iterator i = result.iterator();

                while (i.hasNext()) {
                    returnval.add(((EndEntityProfileDataLocal) i.next()).getProfileName());
                }
            }

            Collections.sort(returnval);
        } catch (Exception e) {
            error("Error getting end entity profile names: ", e);
        }

        return returnval;
    }
     // getEndEntityProfileNames

    /**
     * Retrives end entity profiles sorted by name.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public TreeMap getEndEntityProfiles(Admin admin) {
        TreeMap returnval = new TreeMap();
        Collection result = null;

        try {
            result = profiledatahome.findAll();

            if (result.size() > 0) {
                returnval = new TreeMap();

                Iterator i = result.iterator();

                while (i.hasNext()) {
                    EndEntityProfileDataLocal pdl = (EndEntityProfileDataLocal) i.next();
                    returnval.put(pdl.getProfileName(), pdl.getProfile());
                }
            }
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getEndEntityProfiles

    /**
     * Retrives a named end entity profile.
     *
     * @param admin DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename) {
        EndEntityProfile returnval = null;

        try {
            returnval = (profiledatahome.findByProfileName(profilename)).getProfile();
        } catch (FinderException e) {
            throw new EJBException(e);
        }

        return returnval;
    }
     //  getEndEntityProfile

    /**
     * Finds a end entity profile by id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public EndEntityProfile getEndEntityProfile(Admin admin, int id) {
        EndEntityProfile returnval = null;

        try {
            if (id != 0) {
                returnval = (profiledatahome.findByPrimaryKey(new Integer(id))).getProfile();
            }
        } catch (FinderException e) {
            throw new EJBException(e);
        }

        return returnval;
    }
     // getEndEntityrofile

    /**
     * Retrives the numbers of end entity profiles.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfEndEntityProfiles(Admin admin) {
        int returnval = 0;

        try {
            returnval = (profiledatahome.findAll()).size();
        } catch (FinderException e) {
        }

        return returnval;
    }

    /**
     * Returns a end entity profiles id, given it's profilename
     *
     * @param admin DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     *
     * @return the id or 0 if profile cannot be found.
     */
    public int getEndEntityProfileId(Admin admin, String profilename) {
        int returnval = 0;

        try {
            Integer id = (profiledatahome.findByProfileName(profilename)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getEndEntityrofileId

    /**
     * Returns a end entity profiles name given it's id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return profilename or null if profile id doesn't exists.
     */
    public String getEndEntityProfileName(Admin admin, int id) {
        String returnval = null;

        try {
            returnval = (profiledatahome.findByPrimaryKey(new Integer(id))).getProfileName();
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getEndEntityProfileName

    /**
     * Method to check if a certificateprofile exists in any of the end entity profiles. Used to
     * avoid desyncronization of certificate profile data.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofileid the certificatetype id to search for.
     *
     * @return true if certificateprofile exists in any of the accessrules.
     */
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid) {
        String[] availablecertprofiles = null;
        boolean exists = false;

        try {
            Collection result = profiledatahome.findAll();
            Iterator i = result.iterator();

            while (i.hasNext() && !exists) {
                availablecertprofiles = ((EndEntityProfileDataLocal) i.next()).getProfile()
                                         .getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);

                for (int j = 0; j < availablecertprofiles.length; j++) {
                    if (Integer.parseInt(availablecertprofiles[j]) == certificateprofileid) {
                        exists = true;

                        break;
                    }

                    ;
                }
            }
        } catch (Exception e) {
            error("Error ceching for certificate profile in end entity profiles: ", e);
        }

        return exists;
    }

    // Private methods
    private Integer findFreeEndEntityProfileId() {
        int id = (new Random((new Date()).getTime())).nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1) {
                    profiledatahome.findByPrimaryKey(new Integer(id));
                }

                id++;
            } catch (FinderException e) {
                foundfree = true;
            }
        }

        return new Integer(id);
    }
     // findFreeEndEntityProfileId

    /**
     * Changes the admin preference in the database. Returns false if admin doesn't exist.
     *
     * @param admin DOCUMENT ME!
     * @param serialnumber DOCUMENT ME!
     * @param adminpreference DOCUMENT ME!
     * @param dolog DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private boolean updateAdminPreference(Admin admin, BigInteger serialnumber,
        AdminPreference adminpreference, boolean dolog) {
        debug(">updateAdminPreference(serial : " + serialnumber + ")");

        boolean ret = false;

        try {
            AdminPreferencesDataLocal apdata = adminpreferenceshome.findByPrimaryKey(serialnumber.toString());
            adminpreferenceshome.remove(serialnumber.toString());

            try {
                AdminPreferencesDataLocal apdata2 = adminpreferenceshome.findByPrimaryKey(serialnumber.toString());
            } catch (javax.ejb.FinderException fe) {
            }

            apdata = adminpreferenceshome.create(serialnumber.toString(), adminpreference);

            try {
                AdminPreferencesDataLocal apdata3 = adminpreferenceshome.findByPrimaryKey(serialnumber.toString());
            } catch (javax.ejb.FinderException fe) {
            }

            if (dolog) {
                logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED,
                    "Administrator preference changed.");
            }

            ret = true;
        } catch (javax.ejb.FinderException fe) {
            ret = false;

            if (dolog) {
                try {
                    logsession.log(admin, LogEntry.MODULE_RA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED,
                        "Administrator cannot be found i database.");
                } catch (RemoteException re) {
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }

        debug("<updateAdminPreference()");

        return ret;
    }
     // changeAdminPreference
}
 // LocalRaAdminSessionBean
