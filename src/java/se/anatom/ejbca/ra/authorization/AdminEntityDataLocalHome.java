package se.anatom.ejbca.ra.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see AdminEntityDataDataBean
 *
 * @version $Id: AdminEntityDataLocalHome.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface AdminEntityDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param admingroupname DOCUMENT ME!
     * @param matchwith DOCUMENT ME!
     * @param matchtype DOCUMENT ME!
     * @param matchvalue DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public AdminEntityDataLocal create(String admingroupname, int matchwith, int matchtype,
        String matchvalue) throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param primarykey DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public AdminEntityDataLocal findByPrimaryKey(AdminEntityPK primarykey)
        throws FinderException;
}
