package se.anatom.ejbca.log;

/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionLocalHome.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IRaAdminSessionRemote interface
     *
     * @throws CreateException
     */
    ILogSessionLocal create() throws Exception;
}
