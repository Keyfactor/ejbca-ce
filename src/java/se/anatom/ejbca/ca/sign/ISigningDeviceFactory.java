package se.anatom.ejbca.ca.sign;

import java.util.Properties;

public interface ISigningDeviceFactory
{
 public ISigningDevice makeInstance(Properties prop) throws Exception;
}
