package se.anatom.ejbca.ra.raadmin;


import java.rmi.RemoteException;

import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.UserPreference;

/**
 * For docs, see UserPreferencesDataBean
 *
 * @version $Id: UserPreferencesDataLocal.java,v 1.4 2002-07-22 22:59:58 herrvendil Exp $
 **/

public interface UserPreferencesDataLocal extends javax.ejb.EJBLocalObject {



    // public methods

    public String getId();

    public void setId(String id);

    public UserPreference getUserPreference();

    public void setUserPreference(UserPreference userpreference);

}

