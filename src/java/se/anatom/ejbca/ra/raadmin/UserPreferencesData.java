

package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import java.math.BigInteger;

import se.anatom.ejbca.webdist.webconfiguration.UserPreference;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface UserPreferencesData extends javax.ejb.EJBObject {



    // public methods

    public BigInteger getId() throws RemoteException;

    public void setId(BigInteger id) throws RemoteException;

    public UserPreference getUserPreference() throws RemoteException;

    public void setUserPreference(UserPreference userpreference) throws RemoteException;
    
}

