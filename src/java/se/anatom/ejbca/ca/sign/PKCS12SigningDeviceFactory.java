package se.anatom.ejbca.ca.sign;

import java.util.Properties;

/** Factory for PKCS12 signing device.
 *
 * @version $Id: PKCS12SigningDeviceFactory.java,v 1.4 2002-08-20 12:17:11 anatom Exp $
 */

public class PKCS12SigningDeviceFactory {

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

