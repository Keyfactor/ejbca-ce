package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AccessRulesDataBean
 **/
public interface AuthorizationTreeUpdateDataLocalHome extends javax.ejb.EJBLocalHome {

    public static final int AUTHORIZATIONTREEUPDATEDATA = 1;
    
    public AuthorizationTreeUpdateDataLocal create()
        throws CreateException;
    
    /**
     * Should only be called with the AUTHORIZATIONTREEUPDATEDATA constant.
     */
    public AuthorizationTreeUpdateDataLocal findByPrimaryKey(Integer pk)
        throws FinderException;
}
