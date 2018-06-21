/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.config;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

/**
 * JSON serializer for Jackson to handle a java.util.Date instance and present it in ISO8601 format with UTC timezone.
 *
 * @version $Id: JsonDateSerializer.java 29080 2018-05-31 11:12:13Z andrey_s_helmes $
 */
public class JsonDateSerializer extends JsonSerializer<Date> {

    /**
     * ISO8601 Date format with UTC time zone.
     */
    public static final DateFormat DATE_FORMAT_ISO8601 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    // UTC Time zone.
    private static final TimeZone TIME_ZONE_UTC = TimeZone.getTimeZone("UTC");
    static {
        DATE_FORMAT_ISO8601.setTimeZone(TIME_ZONE_UTC);
    }

    @Override
    public void serialize(final Date date, final JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        final String formattedDate = DATE_FORMAT_ISO8601.format(date);
        jsonGenerator.writeString(formattedDate);
    }

}
