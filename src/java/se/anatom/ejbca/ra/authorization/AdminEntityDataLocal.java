package se.anatom.ejbca.ra.authorization;


/**
 * For docs, see AdminEntityDataBean
 *
 * @version $Id: AdminEntityDataLocal.java,v 1.1 2002-10-24 20:07:06 herrvendil Exp $
 **/

public interface AdminEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public Integer getMatchWith();
    public Integer getMatchType();
    public String  getMatchValue();

    public AdminEntity getAdminEntity();

}

