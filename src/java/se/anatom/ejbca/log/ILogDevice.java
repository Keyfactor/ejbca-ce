package se.anatom.ejbca.log;

import java.util.Date;
import java.security.cert.X509Certificate;

/** 
 * Interface used by EJBCA external log devices such as Log4j. 
 *
 *
 */
public interface ILogDevice extends java.io.Serializable {

   /** 
    * Function used by EJBCA to log information.
    *
    * @param admininfo contains information about the administrator performing the event.
    * @param module indicates the module using the bean.
    * @param time the time the event occured.
    * @param username the name of the user involved or null if no user is involved.
    * @param certificate the certificate involved in the event or null if no certificate is involved.
    * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
    * @param comment comment of the event.
    */
    public void log(Admin admininfo, int module, Date time, String username, X509Certificate certificate, int event, String comment);

}
