package se.anatom.ejbca.authorization;


/**
 * For docs, see AdminEntityDataBean
 *
 * @version $Id: AdminEntityDataLocal.java,v 1.3 2003-09-03 14:49:55 herrvendil Exp $
 **/

public interface AdminEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public int getMatchWith();
    public int getMatchType();
    public String  getMatchValue();

    public AdminEntity getAdminEntity(int caid);

}

