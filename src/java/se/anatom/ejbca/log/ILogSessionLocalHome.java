package se.anatom.ejbca.log;

/**
 * @version $Id: ILogSessionLocalHome.java,v 1.2 2003-01-12 17:16:31 anatom Exp $
 */

public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IRaAdminSessionRemote interface
     */

    ILogSessionLocal create() throws Exception;


}

