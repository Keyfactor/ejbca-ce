package se.anatom.ejbca.ra.authorization;


/**
 * For docs, see UserEnityDataBean
 *
 * @version $Id: UserEntityDataLocal.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 **/

public interface UserEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public Integer getMatchWith();
    public Integer getMatchType();
    public String  getMatchValue();

    public UserEntity getUserEntity();

}

