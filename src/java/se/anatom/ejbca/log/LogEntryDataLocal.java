package se.anatom.ejbca.log;

import java.util.Date;


/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocal.java,v 1.4 2003-06-26 11:43:24 anatom Exp $
 */
public interface LogEntryDataLocal extends javax.ejb.EJBLocalObject {
    // Public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getAdminType();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAdminData();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getModule();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getUsername();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCertificateSNR();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getEvent();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getComment();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeAsDate();
}
