package se.anatom.ejbca.log;

import java.util.Date;

import javax.ejb.CreateException;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.util.StringTools;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a log entry in the log database.
 * Information stored:
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
 * @version $Id: LogEntryDataBean.java,v 1.9 2003-10-01 11:12:07 herrvendil Exp $
 **/

public abstract class LogEntryDataBean extends BaseEntityBean {

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract int getAdminType();
    public abstract void setAdminType(int admintype);

    public abstract String getAdminData();
    public abstract void setAdminData(String admindata);
    
    // The id of the CA performing the event.
    public abstract int getCaId();
    public abstract void setCaId(int caid);

    // Indicates the module (CA,RA ...) using the logsession bean.
    public abstract int getModule();
    public abstract void setModule(int module);

    public abstract long getTime();
    public abstract void setTime(long time);

    public abstract String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
    public abstract void setUsername(String username);

    public abstract String getCertificateSNR();
    public abstract void setCertificateSNR(String certificatesnr);

    public abstract int getEvent();
    public abstract void setEvent(int event);

    public abstract String getComment();
    public abstract void setComment(String comment);

    public Date getTimeAsDate(){
      return new Date(getTime());
    }

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
    public LogEntry getLogEntry(){
      return new LogEntry( getAdminType(), getAdminData(), getCaId(), getModule(), getTimeAsDate(), getUsername(), getCertificateSNR(), getEvent(), getComment());
    }
    //
    // Fields required by Container
    //

    public Integer ejbCreate(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment) throws CreateException {
        setId(id);
        setAdminType(admintype);
        setAdminData(admindata);
        setCaId(caid);
        setModule(module);
        setTime(time.getTime());
        setUsername(StringTools.strip(username));
        setCertificateSNR(certificatesnr);
        setEvent(event);
        setComment(comment);
        
        System.out.println("LogEntyDataBean : create : id =" + id + ", caid = " + caid + ", module = " + module + ", time= " + time.getTime());
        
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
    public void ejbPostCreate(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment) {
        // Do nothing. Required.
    }
}

