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

package org.ejbca.repository.generator.util;

public class StringUtil {

    public static String firstUpperCase(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }

    public static String camelToSnake(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        return input
                .replaceAll("([a-z])([A-Z])", "$1_$2")
                .replaceAll("([A-Z])([A-Z][a-z])", "$1_$2")
                .toUpperCase();
    }

}
