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
 * Based on CESeCore version:
 *      TrustedTime.java 858 2011-05-25 09:22:16Z johane
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

    public Long getPreviousUpdate() { return this.previousUpdate; }
    public Long getNextUpdate() { return this.nextUpdate; }

    public void setNextUpdate(Integer when, Integer poll) {
        Long nextUpdate = Long.valueOf(((poll - when) + delta)*1000);
        if(nextUpdate.longValue() <= 0) { 
            nextUpdate = Long.valueOf(1); 
        }

        if(this.nextUpdate != null) {
            this.previousUpdate = this.nextUpdate;
        } 

        this.nextUpdate = nextUpdate;
    }

    public boolean isSync() { return this.sync; }
    public void setSync(boolean sync) { this.sync = sync; }

    public Date getTime() { return new Date(); }

    public String getSource() { return this.source; }
    public void setSource(String source) { this.source = source; }


    public Double getAccuracy() { return accuracy; }
    public void setAccuracy(final Double accuracy) { this.accuracy = accuracy; }

    public TrustedTime(final Double accuracy) {
        this.accuracy = accuracy;
    }

    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append(this.accuracy).append(";").append(this.stratum).append(";").
            append(this.previousUpdate).append(";").append(this.nextUpdate).
            append(";").append(this.sync).append(this.source);
        return sb.toString();
    }
}
