package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;

import javax.ejb.FinderException;

import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.UserPreference;

/**

 * For docs, see UserPreferencesDataBean

 **/

public interface UserPreferencesDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserPreferencesDataLocal create(BigInteger id, UserPreference userpreference)
        throws CreateException;



    public UserPreferencesDataLocal findByPrimaryKey(BigInteger id)

        throws FinderException;

}

