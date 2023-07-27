/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.catoken;

import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Class for printing properties (for debug purposes) without revealing any pin properties in the log file
 * 
 * @version $Id$
 */
public class PropertiesWithHiddenPIN extends Properties {

    private static final long serialVersionUID = -2240419700704551683L;

    public PropertiesWithHiddenPIN() {
    }

    /**
     * @param defaults
     */
    public PropertiesWithHiddenPIN(Properties defaults) {
        super(defaults);
    }

    @Override
    public synchronized String toString() {
        int max = size() - 1;
        if (max == -1) {
            return "{}";
        }

        final StringBuilder sb = new StringBuilder();
        final Iterator<Map.Entry<Object, Object>> it = entrySet().iterator();

        sb.append('{');
        for (int i = 0;; i++) {
            final Map.Entry<Object, Object> e = it.next();
            final String key = (String) e.getKey();
            final String readValue = (String) e.getValue();
            final String value = readValue != null && readValue.length() > 0 && key.trim().equalsIgnoreCase(CryptoToken.AUTOACTIVATE_PIN_PROPERTY) ? "xxxx"
                    : readValue;
            sb.append(key);
            sb.append('=');
            sb.append(value);

            if (i == max) {
                return sb.append('}').toString();
            }
            sb.append(", ");
        }
    }

}
