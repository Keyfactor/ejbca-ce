package se.anatom.ejbca.ra;

import se.anatom.ejbca.ra.GlobalConfiguration;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see GlobalWebConfigurationBean
 */
public interface GlobalConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param globalconfiguration DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public GlobalConfigurationDataLocal create(String id, GlobalConfiguration globalconfiguration)
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
    public GlobalConfigurationDataLocal findByPrimaryKey(String id)
        throws FinderException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public GlobalConfigurationDataLocal findByConfigurationId(String id)
        throws FinderException;
}
