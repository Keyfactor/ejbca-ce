package se.anatom.ejbca.log;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.Date;

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
 * @version $Id: LogEntryDataBean.java,v 1.3 2003-02-27 08:43:25 anatom Exp $
 **/

public abstract class LogEntryDataBean implements javax.ejb.EntityBean {


    protected EntityContext  ctx;
    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract int getAdminType();
    public abstract void setAdminType(int admintype);

    public abstract String getAdminData();
    public abstract void setAdminData(String admindata);

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

    public LogEntry getLogEntry(){
      return new LogEntry( getAdminType(), getAdminData(), getModule(), getTimeAsDate(), getUsername(), getCertificateSNR(), getEvent(), getComment());
    }
    //
    // Fields required by Container
    //

    public Integer ejbCreate(Integer id, int admintype, String admindata, int module, Date time, String username, String certificatesnr, int event, String comment) throws CreateException {
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

    public void ejbPostCreate(Integer id, int admintype, String admindata, int module, Date time, String username, String certificatesnr, int event, String comment) {
        // Do nothing. Required.
    }

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

