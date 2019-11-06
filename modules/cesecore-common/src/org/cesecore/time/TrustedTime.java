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
package org.cesecore.time;

import java.io.Serializable;
import java.util.Date;

/**
 * This class encapsulates a Date object that represents a trusted time. It also
 * provides information related to thhe trusted time source: accuracy and
 * stratum
 * 
 * @version $Id$
 */
public class TrustedTime implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Integer delta = 1;

    private String source;
    private Double accuracy;
    private Integer stratum;
    private Long previousUpdate; //seconds
    private Long nextUpdate; //seconds
    private boolean sync = false;

    public TrustedTime() { }

    public Integer getStratum() { return stratum; }
    public void setStratum(final Integer stratum) { this.stratum = stratum; }

    public Long getPreviousUpdate() { return previousUpdate; }
    public Long getNextUpdate() { return nextUpdate; }

    public void setNextUpdate(Integer when, Integer poll) {
        Long nextUpdate = (((long) poll - when) + delta)*1000;
        if (nextUpdate <= 0L) { 
            nextUpdate = 1L; 
        }

        if(this.nextUpdate != null) {
            this.previousUpdate = this.nextUpdate;
        } 

        this.nextUpdate = nextUpdate;
    }

    public boolean isSync() { return sync; }
    public void setSync(boolean sync) { this.sync = sync; }

    public Date getTime() { return new Date(); }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }


    public Double getAccuracy() { return accuracy; }
    public void setAccuracy(final Double accuracy) { this.accuracy = accuracy; }

    public TrustedTime(final Double accuracy) {
        this.accuracy = accuracy;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append(accuracy).append(";").append(stratum).append(";").
            append(previousUpdate).append(";").append(nextUpdate).
            append(";").append(sync).append(source);
        return sb.toString();
    }
}
