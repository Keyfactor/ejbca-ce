package se.anatom.ejbca.ra.authorization;

import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.naming.*;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;


/**
 * DOCUMENT ME!
 *
 * @version $Id: AvailableResources.java,v 1.6 2003-07-24 08:43:31 anatom Exp $
 */
public class AvailableResources {
    /**
     * Creates a new instance of AvailableResources
     *
     * @param globalconfiguration GlobalConfiguration
     */
    public AvailableResources(GlobalConfiguration globalconfiguration)
        throws NamingException, CreateException, RemoteException {
        this.profileendings = GlobalConfiguration.ENDENTITYPROFILE_ENDINGS;
        this.profileprefix = GlobalConfiguration.ENDENTITYPROFILEPREFIX;
        this.enableendentityprofilelimitations = globalconfiguration.getEnableEndEntityProfileLimitations();
        this.usehardtokenissuing = globalconfiguration.getIssueHardwareTokens();
        this.usekeyrecovery = globalconfiguration.getEnableKeyRecovery();

        InitialContext jndicontext = new InitialContext();
        Object objl = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(objl,
                IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();

        objl = jndicontext.lookup("AuthorizationSession");

        IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(objl,
                IAuthorizationSessionHome.class);
        authorizationsession = authorizationsessionhome.create();
        authorizationsession.init(globalconfiguration);
    }

    // Public methods

    /**
     * Returns all the resources and subresources from the given subresource
     *
     * @return array of strings of resources
     */
    public String[] getResources() {
        Vector resources = new Vector();
        String[] dummy = {  };

        insertAvailableRules(resources);

        if (enableendentityprofilelimitations) {
            insertAvailableProfileRules(resources);
        }

        if (usehardtokenissuing) {
            for (int i = 0; i < GlobalConfiguration.HARDTOKENRESOURCES.length; i++) {
                resources.addElement(GlobalConfiguration.HARDTOKENRESOURCES[i]);
            }

            resources.addElement("/ra_functionallity" + GlobalConfiguration.HARDTOKEN_RA_ENDING);
            resources.addElement("/log_functionallity/view_log/hardtoken_entries");
        }

        if (usekeyrecovery) {
            resources.addElement("/ra_functionallity" + GlobalConfiguration.KEYRECOVERYRESOURCE);
        }

        Collections.sort(resources);

        return (String[]) resources.toArray(dummy);
    }

    // Private methods
    private void insertAvailableRules(Vector resources) {
        try {
            resources.addAll(authorizationsession.getAvailableAccessRules(
                    new Admin(Admin.TYPE_INTERNALUSER)));
        } catch (RemoteException e) {
        }
    }

    private void insertAvailableProfileRules(Vector resources) {
        Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

        try {
            Collection profilenames = raadminsession.getEndEntityProfileNames(admin);

            if (profilenames != null) {
                Iterator i = profilenames.iterator();

                while (i.hasNext()) {
                    String name = (String) i.next();
                    int id = raadminsession.getEndEntityProfileId(admin, name);
                    resources.addElement(profileprefix + id);

                    for (int j = 0; j < profileendings.length; j++) {
                        resources.addElement(profileprefix + id + profileendings[j]);
                    }

                    if (usehardtokenissuing) {
                        resources.addElement(profileprefix + id +
                            GlobalConfiguration.HARDTOKEN_RA_ENDING);
                    }

                    if (usekeyrecovery) {
                        resources.addElement(profileprefix + id +
                            GlobalConfiguration.KEYRECOVERYRESOURCE);
                    }
                }
            }
        } catch (RemoteException e) {
        }
    }

    // Private fields
    private String[] profileendings;
    private String profileprefix;
    private IRaAdminSessionRemote raadminsession;
    private IAuthorizationSessionRemote authorizationsession;
    private boolean enableendentityprofilelimitations;
    private boolean usehardtokenissuing;
    private boolean usekeyrecovery;
}
