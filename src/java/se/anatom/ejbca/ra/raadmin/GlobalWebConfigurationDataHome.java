package se.anatom.ejbca.ra.raadmin;

import java.rmi.RemoteException;

import javax.ejb.CreateException;

import javax.ejb.FinderException;

import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;

/**

 * For docs, see GlobalWebConfigurationDataBean

 **/

public interface GlobalWebConfigurationDataHome extends javax.ejb.EJBHome {



    public GlobalWebConfigurationData create(Integer id, GlobalConfiguration globalconfiguration)

        throws CreateException,  RemoteException;



    public GlobalWebConfigurationData findByPrimaryKey(Integer id)

        throws FinderException, RemoteException;


    public GlobalWebConfigurationData findByConfigurationId(Integer id)

        throws FinderException, RemoteException;

}

