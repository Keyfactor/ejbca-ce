package se.anatom.ejbca.ra.raadmin;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;


/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocalHome.java,v 1.3 2003-07-24 08:43:32 anatom Exp $
 */
public interface EndEntityProfileDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param profilename DOCUMENT ME!
     * @param profile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public EndEntityProfileDataLocal create(Integer id, String profilename, EndEntityProfile profile)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public EndEntityProfileDataLocal findByPrimaryKey(Integer id)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param name DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public EndEntityProfileDataLocal findByProfileName(String name)
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
