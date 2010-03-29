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


/** Class wraps keystring properties. The properties passed in to it can contain fields as the constants:
 *    certSignKey fooalias
 *    testKey testalias
 *    defaultKey defaultalias
 *  When the stirng are added they are mapped to different key purposes, SecConst.CAKEYPURPOSE_CERTSIGN etc. 
 *  When the method getString is called with SecConst.CAKEYPURPOSE_CERTSIGN it will return fooalias, if getString is called
 *  with a key purpose that was not specified, for example SecConst.CAKEYPURPOSE_KEYENCRYPT it will return defaultalias.
 *  
 *   The returned values are supposed to be used to get keys for different aliases from a keystore.
 * 
 * @version $Id$
*/
public class KeyStrings {
    
    final static public String CAKEYPURPOSE_CERTSIGN_STRING = "certSignKey";
    final static public String CAKEYPURPOSE_CRLSIGN_STRING = "crlSignKey";
    final static public String CAKEYPURPOSE_KEYENCRYPT_STRING = "keyEncryptKey";
    final static public String CAKEYPURPOSE_TESTKEY_STRING = "testKey";
    final static public String CAKEYPURPOSE_DEFAULT_STRING = "defaultKey";
    final static public String CAKEYPURPOSE_HARDTOKENENCRYPT_STRING = "hardTokenEncrypt";
    final static public String CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS = "previousCertSignKey";
    final static public String CAKEYPURPOSE_CERTSIGN_STRING_NEXT = "nextCertSignKey";
    final private Map map;
    final private Map keymap;
    final String defaultKeyS;
    public KeyStrings(Properties properties) {
    	{
    		String tmpS = null;
    		if (properties != null) {
    			tmpS = properties.getProperty(CAKEYPURPOSE_DEFAULT_STRING);
    		}
    		defaultKeyS = tmpS!=null ? tmpS.trim() : null;
    	}
    	map = new Hashtable();
    	keymap = new Hashtable();
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
    	addKey(CAKEYPURPOSE_HARDTOKENENCRYPT_STRING,
    			SecConst.CAKEYPURPOSE_HARDTOKENENCRYPT,
    			properties);    		
    	addKey(CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS,
    			SecConst.CAKEYPURPOSE_CERTSIGN_PREVIOUS,
    			properties);    		
    	addKey(CAKEYPURPOSE_CERTSIGN_STRING_NEXT,
    			SecConst.CAKEYPURPOSE_CERTSIGN_NEXT,
    			properties);    		
    } 
    private void addKey(String keyS, int keyI,
                        Properties properties) {
        String value = properties.getProperty(keyS);
        if ( value!=null && value.length()>0 ) {
            value = value.trim();
            map.put(new Integer(keyI), value);
            keymap.put(new Integer(keyI), keyS);
        }
    }
    public String getString(int key) {
        String s;
        try {
            s = (String)map.get(new Integer(key));
        } catch(Exception e) {
            s = null;
        }
        if ( s!=null && s.length()>0 ) {
            return s;
        }
        return defaultKeyS;
    }
    /** Returns which property key is used for a certain key purpose. 
     * For example for SecConst.CAKEYPURPOSE_CERTSIGN would either CAKEYPURPOSE_CERTSIGN_STRING (certSignKey) 
     * or CAKEYPURPOSE_DEFAULT_STRING (defaultKey) be returned.
     */ 
    public String getKey(int key) {
        String s;
        try {
            s = (String)keymap.get(new Integer(key));
        } catch(Exception e) {
            s = null;
        }
        if ( s!=null && s.length()>0 ) {
            return s;
        }
        return CAKEYPURPOSE_DEFAULT_STRING;
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
