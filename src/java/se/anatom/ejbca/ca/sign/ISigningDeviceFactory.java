package se.anatom.ejbca.ca.sign;

import java.util.Properties;


/**
 * Interface for a factory for ISigningDevices.
 *
 * @version $Id$
 */
public interface ISigningDeviceFactory {
    /**
     * Interface for creating an instance of a signing device
     *
     * @param prop properties used as arguments when creating signing device
     *
     * @return Signing Device
     *
     * @throws Exception error
     */
    public ISigningDevice makeInstance(Properties prop)
        throws Exception;
}
