package se.anatom.ejbca.ra.raadmin;

import se.anatom.ejbca.ra.raadmin.EndEntityProfile;

import java.util.Collection;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see EndEntityProfileDataBean
 *
 * @version $Id: EndEntityProfileDataLocalHome.java,v 1.2 2003-06-26 11:43:25 anatom Exp $
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
