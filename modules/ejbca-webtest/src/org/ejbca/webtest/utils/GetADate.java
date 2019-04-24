package org.ejbca.webtest.utils;

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
