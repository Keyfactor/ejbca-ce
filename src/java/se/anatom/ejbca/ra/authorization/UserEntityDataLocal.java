package se.anatom.ejbca.ra.authorization;


/**
 * For docs, see UserEnityDataBean
 **/

public interface UserEntityDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public Integer getMatchWith();
    public Integer getMatchType();
    public String  getMatchValue();
    
    public UserEntity getUserEntity();
   
}

