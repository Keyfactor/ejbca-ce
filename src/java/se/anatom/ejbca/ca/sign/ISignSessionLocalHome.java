
package se.anatom.ejbca.ca.sign;

import javax.ejb.CreateException;
import se.anatom.ejbca.log.Admin;
/**
 * @version $Id: ISignSessionLocalHome.java,v 1.2 2002-09-12 18:14:14 herrvendil Exp $
 */
public interface ISignSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ISignSessionRemote interface
     */
    ISignSessionLocal create(Admin administrator) throws CreateException;
}
