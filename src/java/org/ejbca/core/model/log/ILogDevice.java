/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Interface used by EJBCA external log devices such as Log4j.
 * @version $Id: ILogDevice.java,v 1.1 2006-01-17 20:28:08 anatom Exp $
 */
public interface ILogDevice extends Serializable {

    /**
     * Function used by EJBCA to log information.
     *
     * @see #log(Admin, int, int, Date, String, X509Certificate, int, String, Exception)
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment);

    /**
     * Log information.
     * @param admininfo contains information about the administrator performing the event.
     * @param caid the id of the catch (connected to the event.
     * @param module indicates the module using the bean.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogEntry.EVENT_ constants.
     * @param comment comment of the event.
     * @param exception the exception that has occurred (can be null)
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception);

}
