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
 
package se.anatom.ejbca.log;

import java.util.Properties;


/**
 * Factory for Log4j log device.
 *
 * @version $Id: Log4jLogDeviceFactory.java,v 1.3 2004-04-16 07:38:57 anatom Exp $
 */
public class Log4jLogDeviceFactory {
    /**
     * Creates a new Log4jLogDeviceFactory object.
     */
    public Log4jLogDeviceFactory() {
    }

    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @param prop Arguments needed for the eventual creation of the object
     *
     * @return An instance of the log device.
     */
    public synchronized ILogDevice makeInstance(Properties prop)
        throws Exception {
        return Log4jLogDevice.instance(prop);
    }
}
