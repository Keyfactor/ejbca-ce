package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing  accessrules in EJBCA authorization module
 * Information stored:
 * <pre>
 * Access rule
 * rule (accept of decline)
 * isrecursive
 * 
 * </pre>
 *
 * @version $Id: AuthorizationTreeUpdateDataBean.java,v 1.1 2003-09-04 14:26:37 herrvendil Exp $
 */
public abstract class AuthorizationTreeUpdateDataBean extends BaseEntityBean
{

    private static Logger log = Logger.getLogger(AuthorizationTreeUpdateDataBean.class);

    public abstract Integer getPK();
    public abstract void setPK(Integer pK);

    public abstract int getAuthorizationTreeUpdateNumber();
    public abstract void setAuthorizationTreeUpdateNumber(int authorizationtreeupdatenumber);

    
    //
    // Fields required by Container
    //
    public Integer ejbCreate() throws CreateException {
      setPK(new Integer(AuthorizationTreeUpdateDataLocalHome.AUTHORIZATIONTREEUPDATEDATA));
      setAuthorizationTreeUpdateNumber(0);
      return new Integer(AuthorizationTreeUpdateDataLocalHome.AUTHORIZATIONTREEUPDATEDATA);
    }

    public void ejbPostCreate() {
        // Do nothing. Required method.
    }

     /**
     * @see se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocal
     */
    
    public boolean updateNeccessary(int currentauthorizationtreeupdatenumber){
      return getAuthorizationTreeUpdateNumber() != currentauthorizationtreeupdatenumber;          
    } // updateNeccessary
    

     /**
     * @see se.anatom.ejbca.authorization.AuthorizationTreeUpdateDataLocal
     */
    
    public void incrementAuthorizationTreeUpdateNumber(){
      setAuthorizationTreeUpdateNumber(getAuthorizationTreeUpdateNumber() +1);  
    }  // incrementAuthorizationTreeUpdateNumber

}
