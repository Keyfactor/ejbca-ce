package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.util.Collection;

/**

 * For docs, see AvailableAccessRulesDataBean

 **/

public interface AvailableAccessRulesDataLocalHome extends javax.ejb.EJBLocalHome {

    public AvailableAccessRulesDataLocal create(String name)
        throws CreateException;


    public AvailableAccessRulesDataLocal findByPrimaryKey(String name)
        throws FinderException;
    
    public Collection findAll() throws FinderException;
}

