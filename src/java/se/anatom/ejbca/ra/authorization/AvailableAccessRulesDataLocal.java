package se.anatom.ejbca.ra.authorization;


import java.rmi.RemoteException;


/**

 * For docs, see GlobalWebConfigurationDataBean

 **/

public interface AvailableAccessRulesDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public String getName();
    public void setName(String name);

}

