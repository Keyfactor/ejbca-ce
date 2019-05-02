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
package org.ejbca.webtest.utils;

/**
 * Helper class used for returning an Iso formatted date.
 *
 * @version $Id: GetADate.java 32091 2019-05-02 12:59:46Z margaret_d_thomas $
 *
 */
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

public class GetADate {

    /**
     * Return a current ISO 8601 Date formatted as string
     *
     * @return
     */
    public String getIso8601Date() {
        //Backdate 2 days from current
        Date date = new Date(System.currentTimeMillis());
        Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.DATE, -2);
        Date dateModified = cal.getTime();

        // Format the date accordingly
        SimpleDateFormat sdf;
        sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("CET"));

        return sdf.format(dateModified);
    }
}
