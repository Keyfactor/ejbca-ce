package se.anatom.ejbca.ca.sign;

import java.util.Properties;

/** Factory for PKCS12 signing device.
 *
 * @version $Id: PKCS12SigningDeviceFactory.java,v 1.7 2003-03-01 23:58:21 koen_serry Exp $
 */

public class PKCS12SigningDeviceFactory implements ISigningDeviceFactory {

    public PKCS12SigningDeviceFactory() {
    }

   /** Creates (if needed) the signing device and returns the object.
    * @param prop Arguments needed for the eventual creation of the object
    * @return An instance of the Signing device.
    */
    public synchronized ISigningDevice makeInstance(Properties prop) throws Exception {
        return PKCS12SigningDevice.instance(prop);
    }

}

