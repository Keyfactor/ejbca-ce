package se.anatom.ejbca.ra.raadmin;


import java.rmi.RemoteException;

import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.UserPreference;

/**
 * For docs, see UserPreferencesDataBean
 *
 * @version $Id: UserPreferencesDataLocal.java,v 1.3 2002-07-22 10:38:48 anatom Exp $
 **/

public interface UserPreferencesDataLocal extends javax.ejb.EJBLocalObject {



    // public methods

    public BigInteger getId();

    public void setId(BigInteger id);

    public UserPreference getUserPreference();

    public void setUserPreference(UserPreference userpreference);

}

