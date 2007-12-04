package org.ejbca.core.model.log;

import java.util.Properties;

public class ProtectedLogDeviceFactory {

    /**
     * Creates a new ProtectedLogDeviceFactory object.
     */
    public ProtectedLogDeviceFactory() {
    }
    
    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @param prop Arguments needed for the eventual creation of the object
     *
     * @return An instance of the log device.
     */
    public synchronized ILogDevice makeInstance(Properties prop) throws Exception {
        return ProtectedLogDevice.instance(prop);
    }
}

