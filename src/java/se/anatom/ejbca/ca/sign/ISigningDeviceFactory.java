package se.anatom.ejbca.ca.sign;

import java.util.Properties;

/**
 * Interface for a factory for ISigningDevices.
 *
 * @version $Id$
 */
public interface ISigningDeviceFactory
{
    public ISigningDevice makeInstance(Properties prop) throws Exception;
}
