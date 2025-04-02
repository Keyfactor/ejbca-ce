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
package org.cesecore.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class ConverterUtils {

    public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public static String localDateTimeToString(final LocalDateTime localDateTime) {
        if (localDateTime == null) {
            return null;
        }
        else {
            return localDateTime.format(DATE_TIME_FORMATTER);
        }
    }

    public static LocalDateTime parseLocalDateTime(final String localDateTimeAsString) {
        if (localDateTimeAsString == null) {
            return null;
        }
        else {
            return LocalDateTime.parse(localDateTimeAsString, DATE_TIME_FORMATTER);
        }
    }

}
