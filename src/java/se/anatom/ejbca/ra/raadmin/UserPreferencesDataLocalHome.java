package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;

import javax.ejb.FinderException;

import java.math.BigInteger;

import se.anatom.ejbca.ra.raadmin.UserPreference;

/**
 * For docs, see UserPreferencesDataBean
 *
 * @version $Id: UserPreferencesDataLocalHome.java,v 1.4 2002-07-22 23:00:41 herrvendil Exp $
 **/

public interface UserPreferencesDataLocalHome extends javax.ejb.EJBLocalHome {

    public UserPreferencesDataLocal create(String id, UserPreference userpreference)
        throws CreateException;



    public UserPreferencesDataLocal findByPrimaryKey(String id)

        throws FinderException;

}

