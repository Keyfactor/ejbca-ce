package se.anatom.ejbca.log;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see LogConfigurationDataBean
 */
public interface LogConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param logconfiguration DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public LogConfigurationDataLocal create(Integer id, LogConfiguration logconfiguration)
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
    public LogConfigurationDataLocal findByPrimaryKey(Integer id)
        throws FinderException;
}
