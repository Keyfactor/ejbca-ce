package se.anatom.ejbca.ca.sign;

import java.util.Properties;

import org.apache.log4j.*;

/** Factory for PKCS12 signingdevice..
 *
 * @version $Id: PKCS12SigningDeviceFactory.java,v 1.2 2002-07-20 18:40:08 herrvendil Exp $
 */

public class PKCS12SigningDeviceFactory {

    /** Log4j instance for Base */
    private static Category cat = Category.getInstance( PKCS12SigningDevice.class.getName() );

    public PKCS12SigningDeviceFactory() {
    }

   /** Creates (if needed) the signing device and returns the object.
    * prop Arguments needed för the eventual creation of the object
    * @return An instance of the Signing device.
    */
    public synchronized ISigningDevice makeInstance(Properties prop) throws Exception {
        return new PKCS12SigningDevice(prop);
    }

}

