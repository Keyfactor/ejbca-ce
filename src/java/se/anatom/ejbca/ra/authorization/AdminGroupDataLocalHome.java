package se.anatom.ejbca.ra.authorization;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see AdminGroupDataBean
 *
 * @version $Id: AdminGroupDataLocalHome.java,v 1.2 2003-06-26 11:43:24 anatom Exp $
 */
public interface AdminGroupDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param admingroupname DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public AdminGroupDataLocal create(String admingroupname)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param admingroupname DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public AdminGroupDataLocal findByPrimaryKey(String admingroupname)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public Collection findAll() throws FinderException;
}
