package se.anatom.ejbca.log;

import java.util.Date;

import javax.ejb.CreateException;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.util.StringTools;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * log entry in the log database. Information stored:
 * <pre>
 *  id (Primary Key)
 *  admintype is pricipally the type of data stored in the admindata field, should be one of se.anatom.ejbca.log.Admin.TYPE_ constants.
 *  admindata is the data identifying the administrator, should be certificate snr or ip-address when no certificate could be retrieved.
 *  time is the time the event occured.
 *  username the name of the user involved or null if no user is involved.
 *  certificate the certificate involved in the event or null if no certificate is involved.
 *  event is id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
 *  comment an optional comment of the event.
 * </pre>
 *
 * @version $Id: LogEntryDataBean.java,v 1.7 2003-07-24 08:43:31 anatom Exp $
 */
public abstract class LogEntryDataBean extends BaseEntityBean {
    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     */
    public abstract void setId(Integer id);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getAdminType();

    /**
     * DOCUMENT ME!
     *
     * @param admintype DOCUMENT ME!
     */
    public abstract void setAdminType(int admintype);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getAdminData();

    /**
     * DOCUMENT ME!
     *
     * @param admindata DOCUMENT ME!
     */
    public abstract void setAdminData(String admindata);

    // Indicates the module (CA,RA ...) using the logsession bean.
    public abstract int getModule();

    /**
     * DOCUMENT ME!
     *
     * @param module DOCUMENT ME!
     */
    public abstract void setModule(int module);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract long getTime();

    /**
     * DOCUMENT ME!
     *
     * @param time DOCUMENT ME!
     */
    public abstract void setTime(long time);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     *
     * @see se.anatom.ejbca.util.StringTools
     */
    public abstract void setUsername(String username);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getCertificateSNR();

    /**
     * DOCUMENT ME!
     *
     * @param certificatesnr DOCUMENT ME!
     */
    public abstract void setCertificateSNR(String certificatesnr);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract int getEvent();

    /**
     * DOCUMENT ME!
     *
     * @param event DOCUMENT ME!
     */
    public abstract void setEvent(int event);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public abstract String getComment();

    /**
     * DOCUMENT ME!
     *
     * @param comment DOCUMENT ME!
     */
    public abstract void setComment(String comment);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Date getTimeAsDate() {
        return new Date(getTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public LogEntry getLogEntry() {
        return new LogEntry(getAdminType(), getAdminData(), getModule(), getTimeAsDate(),
            getUsername(), getCertificateSNR(), getEvent(), getComment());
    }

    //
    // Fields required by Container
    //
    public Integer ejbCreate(Integer id, int admintype, String admindata, int module, Date time,
        String username, String certificatesnr, int event, String comment)
        throws CreateException {
        setId(id);
        setAdminType(admintype);
        setAdminData(admindata);
        setModule(module);
        setTime(time.getTime());
        setUsername(StringTools.strip(username));
        setCertificateSNR(certificatesnr);
        setEvent(event);
        setComment(comment);

        return id;
    }

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
     */
    public void ejbPostCreate(Integer id, int admintype, String admindata, int module, Date time,
        String username, String certificatesnr, int event, String comment) {
        // Do nothing. Required.
    }
}
