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

package org.ejbca.util;

import java.util.HashMap;
import java.util.Map;


/** An implementation of HashMap that base64 decodes all String's that you 'get', 
 * if they start with 'B64', i.e. it base64 decodes string of form "B64:<base64 encoded string>".
 * It only tries to decode objects of type String.
 *  
 * @author tomasg
 * @version $Id$
 */
public class Base64GetHashMap extends HashMap {
    public Base64GetHashMap() {
        super();
    }
    public Base64GetHashMap(Map m) {
        super(m);
    }
    
    public Object get(Object key) {
        Object o = super.get(key);
        if (o == null) {
            return o;
        }
        if (o instanceof String) {
            String s = (String) o;
            return StringTools.getBase64String(s);                       
        }
        return o;
    }
    
}
