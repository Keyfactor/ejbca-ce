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

package org.ejbca.core.model.ca.catoken;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.ejbca.core.model.SecConst;


/**
 * 
 * @version $Id: KeyStrings.java,v 1.2 2006-05-05 14:36:59 herrvendil Exp $
*/
public class KeyStrings {
    
    final private String CAKEYPURPOSE_CERTSIGN_STRING = "certSignKey";
    final private String CAKEYPURPOSE_CRLSIGN_STRING = "crlSignKey";
    final private String CAKEYPURPOSE_KEYENCRYPT_STRING = "keyEncryptKey";
    final private String CAKEYPURPOSE_TESTKEY_STRING = "testKey";
    final private String CAKEYPURPOSE_DEFAULT_STRING = "defaultKey";
    final private Map map;
    final String defaultKeyS;
    public KeyStrings(Properties properties) {
        {
            String tmpS = properties.getProperty(
                CAKEYPURPOSE_DEFAULT_STRING);
            defaultKeyS = tmpS!=null ? tmpS.trim() : null;
        }
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
        addKey(CAKEYPURPOSE_TESTKEY_STRING,
                SecConst.CAKEYPURPOSE_KEYTEST,
                properties);
    }
    private void addKey(String keyS, int keyI,
                        Properties properties) {
        String value = properties.getProperty(keyS);
        if ( value!=null && value.length()>0 ) {
            value = value.trim();
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
        if(defaultKeyS != null){
          set.add(defaultKeyS);
        }
        return (String[])set.toArray(new String[0]);
    }
}
