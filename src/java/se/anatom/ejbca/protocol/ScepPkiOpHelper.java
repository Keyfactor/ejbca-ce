package se.anatom.ejbca.protocol;

import java.io.IOException;

import org.apache.log4j.Logger;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id: ScepPkiOpHelper.java,v 1.7 2003-06-01 11:26:58 anatom Exp $
 */
public class ScepPkiOpHelper {

    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);

    public ScepPkiOpHelper(byte[] msg) {
        log.debug(">ScepPkiOpHelper("+msg.length+" bytes)");
        try {
            PKCS7RequestMessage req = new PKCS7RequestMessage(msg);
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ",e);
        }    
        log.debug("<ScepPkiOpHelper");
    }

}
