package se.anatom.ejbca.log;

import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocalHome.java,v 1.3 2003-06-26 11:43:24 anatom Exp $
 */
public interface LogEntryDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param admintype DOCUMENT ME!
     * @param admindata DOCUMENT ME!
     * @param module DOCUMENT ME!
     * @param time DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param certificatesnr DOCUMENT ME!
     * @param event DOCUMENT ME!
     * @param comment DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public LogEntryDataLocal create(Integer id, int admintype, String admindata, int module,
        Date time, String username, String certificatesnr, int event, String comment)
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
    public LogEntryDataLocal findByPrimaryKey(Integer id)
        throws FinderException;
}
