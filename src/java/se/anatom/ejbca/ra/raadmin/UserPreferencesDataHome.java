package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;

import javax.ejb.FinderException;

import java.math.BigInteger;

import se.anatom.ejbca.webdist.webconfiguration.UserPreference;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface UserPreferencesDataHome extends javax.ejb.EJBHome {



    public UserPreferencesData create(BigInteger id, UserPreference userpreference)

        throws CreateException,  RemoteException;



    public UserPreferencesData findByPrimaryKey(BigInteger id)

        throws FinderException, RemoteException;

}

