/*
 * cProfileNameProxy.java
 *
 * Created on den 23 juli 2002, 17:49
 */
package se.anatom.ejbca.webdist.rainterface;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

import java.rmi.RemoteException;

import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import javax.naming.*;


/**
 * A class used to improve performance by proxying end entity profileid to profilename mappings by
 * minimizing the number of needed lockups over rmi.
 *
 * @version $Id: EndEntityProfileNameProxy.java,v 1.3 2003-06-26 11:43:26 anatom Exp $
 */
public class EndEntityProfileNameProxy {
    /**
     * Creates a new instance of ProfileNameProxy
     *
     * @param administrator administrator using this class
     */
    public EndEntityProfileNameProxy(Admin administrator)
        throws RemoteException, NamingException, FinderException, CreateException {
        // Get the RaAdminSession instance.
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                    "RaAdminSession"), IRaAdminSessionHome.class);
        raadminsession = raadminsessionhome.create();

        profilenamestore = new HashMap();
        this.administrator = administrator;
    }

    /**
     * Method that first tries to find profilename in local hashmap and if it doesn't exists looks
     * it up over RMI.
     *
     * @param profileid the profile id number to look up.
     *
     * @return the profilename or null if no profilename is relatied to the given id
     */
    public String getEndEntityProfileName(int profileid)
        throws RemoteException {
        String returnval = null;

        // Check if name is in hashmap
        returnval = (String) profilenamestore.get(new Integer(profileid));

        if (returnval == null) {
            // Retreive profilename over RMI
            returnval = raadminsession.getEndEntityProfileName(administrator, profileid);

            if (returnval != null) {
                profilenamestore.put(new Integer(profileid), returnval);
            }
        }

        return returnval;
    }

    // Private fields
    private HashMap profilenamestore;
    private IRaAdminSessionRemote raadminsession;
    private Admin administrator;
}
