
package se.anatom.ejbca.ra;

import javax.ejb.CreateException;


/**
 * @version $Id: IUserAdminSessionLocalHome.java,v 1.1 2003-09-04 08:51:44 herrvendil Exp $
 */
public interface IUserAdminSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IUserAdminSessionLocal interface
     */
    IUserAdminSessionLocal create() throws CreateException;

}
