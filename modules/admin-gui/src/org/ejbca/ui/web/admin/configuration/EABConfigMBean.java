/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.admin.configuration;

import org.ejbca.core.EjbcaException;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Backing bean for edit EAB config view.
 *
 */
public class EABConfigMBean {


    public static Map<String, Set<String>> parseCsvToMap(final byte[] bytes, String delimeter) throws EjbcaException {
        delimeter = delimeter == null ? "," : delimeter;
        if (bytes == null) {
            return null;
        }
        Map<String, Set<String>> result = new HashMap<>();
        try {
            final ByteArrayInputStream stream = new ByteArrayInputStream(bytes);
            BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
            String row;
            while ((row = reader.readLine()) != null) {
                String[] data = row.split(delimeter);
                if (data.length != 2) {
                    throw new EjbcaException("Wrong file format");
                }
                final String namespace = data[0].trim();
                result.computeIfAbsent(namespace, k -> new HashSet<String>());
                result.get(namespace).add(data[1].trim());
            }
            reader.close();
        } catch (IOException e) {
            throw new EjbcaException("Failed to read file content", e);
        }
        return result;
    }
}
