package se.anatom.ejbca.authorization;


/**
 * For docs, see AdminEntityDataBean
 *
 * @version $Id: AdminEntityDataLocal.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 **/

public interface AdminEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public int getMatchWith();
    public int getMatchType();
    public String  getMatchValue();

    public AdminEntity getAdminEntity(int caid);

}

