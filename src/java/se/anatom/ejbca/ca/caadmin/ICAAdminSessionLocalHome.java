
package se.anatom.ejbca.ca.caadmin;

import javax.ejb.CreateException;

/**
 * @version $Id: ICAAdminSessionLocalHome.java,v 1.1 2003-09-03 16:21:29 herrvendil Exp $
 */
public interface ICAAdminSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ICAAdminSessionLocal interface
     */
    ICAAdminSessionLocal create() throws CreateException;
}
