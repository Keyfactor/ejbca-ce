package se.anatom.ejbca.log;

import java.util.Properties;

/** Factory for Log4j log device.
 *
 * @version $Id: Log4jLogDeviceFactory.java,v 1.1 2002-09-12 17:12:13 herrvendil Exp $
 */

public class Log4jLogDeviceFactory {

    public Log4jLogDeviceFactory() {
    }

   /** Creates (if needed) the log device and returns the object.
    *
    * @param prop Arguments needed for the eventual creation of the object
    * @return An instance of the log device.
    */
    public synchronized ILogDevice makeInstance(Properties prop) throws Exception {
        return Log4jLogDevice.instance(prop);
    }

}

