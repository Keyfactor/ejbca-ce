package se.anatom.ejbca.log;

import org.apache.log4j.Logger;

import java.security.cert.X509Certificate;

import java.util.Date;
import java.util.Properties;


/**
 * Implements a log device using Log4j, implementes the Singleton pattern.
 *
 * @version $Id: Log4jLogDevice.java,v 1.5 2003-06-26 11:43:24 anatom Exp $
 */
public class Log4jLogDevice implements ILogDevice, java.io.Serializable {
    /** Log4j instance for Base */
    private static Logger log = Logger.getLogger(Log4jLogDevice.class);

    /** A handle to the unique Singleton instance. */
    private static Log4jLogDevice instance = null;

    /**
     * Initializes all internal data
     *
     * @param prop Arguments needed for the eventual creation of the object
     */
    protected Log4jLogDevice(Properties prop) throws Exception {
        // Do nothing
    }

    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @param prop Arguments needed for the eventual creation of the object
     *
     * @return An instance of the log device.
     */
    public static synchronized ILogDevice instance(Properties prop)
        throws Exception {
        if (instance == null) {
            instance = new Log4jLogDevice(prop);
        }

        return instance;
    }

    /**
     * @see se.anatom.ejbca.log.ILogDevice
     */
    public void log(Admin admininfo, int module, Date time, String username,
        X509Certificate certificate, int event, String comment) {
        String user = "No User Involved";
        String cert = "No Certificate Involved";
        String admin = "Administrator not known";

        if (username != null) {
            user = username;
        }

        if (certificate != null) {
            cert = certificate.getSerialNumber().toString(16);
        }

        if (admininfo.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
            admin = Admin.ADMINTYPETEXTS[Admin.TYPE_CLIENTCERT_USER] + ", Certificate SNR : " +
                admininfo.getAdminData();
        } else if (admininfo.getAdminType() == Admin.TYPE_PUBLIC_WEB_USER) {
            if (admininfo.getAdminData() != null) {
                if (!admininfo.getAdminData().equals("")) {
                    admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER] + ", IP Address : " +
                        admininfo.getAdminData();
                }
            } else {
                admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER];
            }
        } else {
            admin = Admin.ADMINTYPETEXTS[admininfo.getAdminType()];
        }

        if (event < LogEntry.EVENT_ERROR_BOUNDRARY) {
            // Do Log4j Informational logging.             
            log.info(time.toGMTString() + ", " + LogEntry.MODULETEXTS[module] + ", " +
                LogEntry.EVENTNAMES_INFO[event] + ", Administrator : " + admin + ", User : " +
                user + ", Certificate : " + cert + ", Comment : " + comment);
        } else {
            // Do Log4j error logging.   
            log.error(time.toGMTString() + ", " + LogEntry.MODULETEXTS[module] + ", " +
                LogEntry.EVENTNAMES_ERROR[event - LogEntry.EVENT_ERROR_BOUNDRARY] +
                ", Administrator : " + admin + ", User : " + user + ", Certificate : " + cert +
                ", Comment : " + comment);
        }
    }

    /**
     * @see se.anatom.ejbca.log.ILogDevice
     */
    public void log(Admin admininfo, int module, Date time, String username,
        X509Certificate certificate, int event, String comment, Exception exception) {
        log(admininfo, module, time, username, certificate, event, comment);
        log.error("Exception : ", exception);
    }
}
