package se.anatom.ejbca.protocol;

import java.io.IOException;

import org.apache.log4j.*;


/** Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
*
* @version  $Id: ScepPkiOpHelper.java,v 1.5 2002-10-13 11:40:28 anatom Exp $
*/
public class ScepPkiOpHelper {

    static private Category cat = Category.getInstance( ScepPkiOpHelper.class.getName() );

    public ScepPkiOpHelper(byte[] msg) {
        cat.debug(">ScepPkiOpHelper");
        try {
            PKCS7RequestMessage req = new PKCS7RequestMessage(msg);
        } catch (IOException e) {
        }    
        cat.debug("<ScepPkiOpHelper");
    }

}