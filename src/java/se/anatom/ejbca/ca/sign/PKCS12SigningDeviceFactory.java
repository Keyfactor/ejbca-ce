package se.anatom.ejbca.ca.sign;

import java.util.Properties;

import org.apache.log4j.*;

/** Factory for PKCS12 signing device.
 *
 * @version $Id: PKCS12SigningDeviceFactory.java,v 1.3 2002-07-21 12:12:12 anatom Exp $
 */

public class PKCS12SigningDeviceFactory {

    /** Log4j instance for Base */
    private static Category cat = Category.getInstance( PKCS12SigningDevice.class.getName() );

    public PKCS12SigningDeviceFactory() {
    }

   /** Creates (if needed) the signing device and returns the object.
    * @param prop Arguments needed fo?r the eventual creation of the object
    * @return An instance of the Signing device.
    */
    public synchronized ISigningDevice makeInstance(Properties prop) throws Exception {
        return PKCS12SigningDevice.instance(prop);
    }

}

