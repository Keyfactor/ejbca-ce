/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package se.anatom.ejbca.ca.caadmin.hardcatokens;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;

/**
 * 
 * @version $Id: KeyStrings.java,v 1.1 2005-06-10 08:12:52 anatom Exp $
*/
public class KeyStrings {
    
    /** Log4j instance for Base */
    private static transient final Logger log = Logger.getLogger(KeyStrings.class);

    final private String CAKEYPURPOSE_CERTSIGN_STRING = "certSignKey";
    final private String CAKEYPURPOSE_CRLSIGN_STRING = "crlSignKey";
    final private String CAKEYPURPOSE_KEYENCRYPT_STRING = "keyEncryptKey";
    final private String CAKEYPURPOSE_DEFAULT_STRING = "defaultKey";
    final private Map map;
    final String defaultKeyS;
    public KeyStrings(Properties properties) {
        {
            String tmpS = properties.getProperty(
                CAKEYPURPOSE_DEFAULT_STRING);
            defaultKeyS = tmpS!=null ? tmpS.trim() : null;
        }
        if ( defaultKeyS!= null )
            log.debug("CA default key " +
                           CAKEYPURPOSE_DEFAULT_STRING +
                           " with value: " + defaultKeyS);
        map = new Hashtable();
        addKey(CAKEYPURPOSE_CERTSIGN_STRING,
               SecConst.CAKEYPURPOSE_CERTSIGN,
               properties);
        addKey(CAKEYPURPOSE_CRLSIGN_STRING,
               SecConst.CAKEYPURPOSE_CRLSIGN,
               properties);
        addKey(CAKEYPURPOSE_KEYENCRYPT_STRING,
               SecConst.CAKEYPURPOSE_KEYENCRYPT,
               properties);
    }
    private void addKey(String keyS, int keyI,
                        Properties properties) {
        String value = properties.getProperty(keyS);
        if ( value!=null && value.length()>0 ) {
            value = value.trim();
            log.debug("CA key " + keyS + " with nr " + keyI +
                           " added Value: " + value);
            map.put(new Integer(keyI), value);
        }
    }
    public String getString(int key) {
        String s;
        try {
            s = (String)map.get(new Integer(key));
        } catch(Exception e) {
            s = null;
        }
        if ( s!=null && s.length()>0 )
            return s;
        return defaultKeyS;
    }
    public String[] getAllStrings() {
        Set set = new HashSet();
        set.addAll(map.values());
        set.add(defaultKeyS);
        return (String[])set.toArray(new String[0]);
    }
}
