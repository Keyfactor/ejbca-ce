package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import org.apache.log4j.*;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a user entity in EJBCA authorization module
 * Information stored:
 * <pre>
 *   matchwith
 *   matchtype
 *   matchvalue
 * </pre>
 *
 **/

public abstract class UserEntityDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance( UserEntityDataBean.class.getName() );
    protected EntityContext  ctx;

    public abstract UserEntityPK getPK();    
    public abstract Integer      getMatchWith();
    public abstract Integer      getMatchType();
    public abstract String       getMatchValue();

    public abstract void setPK(UserEntityPK pk);    
    public abstract void setMatchWith(Integer matchwith);
    public abstract void setMatchType(Integer matchtype);
    public abstract void setMatchValue(String matchvalue);

    
    public UserEntity getUserEntity(){
      return new UserEntity(getMatchWith().intValue(), getMatchType().intValue(), getMatchValue());
    }
    
    
    //
    // Fields required by Container
    // 


    public UserEntityPK ejbCreate(String usergroupname, int matchwith, int matchtype, String matchvalue) throws CreateException {

        UserEntityPK pk = new UserEntityPK(usergroupname, matchwith,matchtype,matchvalue); 
        setPK(pk);
        setMatchWith(new Integer(matchwith));
        setMatchType(new Integer(matchtype));
        setMatchValue(matchvalue);

        
        log.debug("Created user entity "+ matchvalue);
        return pk;
    }

    public void ejbPostCreate(String usergroupname, int matchwith, int matchtype, String matchvalue) {
        // Do nothing. Required.
    }

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx; 
    }  

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

