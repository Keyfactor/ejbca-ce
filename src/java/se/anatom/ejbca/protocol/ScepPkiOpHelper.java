package se.anatom.ejbca.protocol;

import java.io.IOException;

import org.apache.log4j.Logger;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id: ScepPkiOpHelper.java,v 1.6 2003-02-12 11:23:18 scop Exp $
 */
public class ScepPkiOpHelper {

    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);

    public ScepPkiOpHelper(byte[] msg) {
        log.debug(">ScepPkiOpHelper");
        try {
            PKCS7RequestMessage req = new PKCS7RequestMessage(msg);
        } catch (IOException e) {
        }    
        log.debug("<ScepPkiOpHelper");
    }

}
