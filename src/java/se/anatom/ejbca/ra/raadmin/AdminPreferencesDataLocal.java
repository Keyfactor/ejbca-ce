package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;
import java.math.BigInteger;
import se.anatom.ejbca.ra.raadmin.AdminPreference;

/**
 * For docs, see AdminPreferencesDataBean
 *
 * @version $Id: AdminPreferencesDataLocal.java,v 1.1 2002-10-24 20:09:21 herrvendil Exp $
 **/

public interface AdminPreferencesDataLocal extends javax.ejb.EJBLocalObject {

    // public methods

    public String getId();

    public void setId(String id);

    public AdminPreference getAdminPreference();

    public void setAdminPreference(AdminPreference adminpreference);

}

