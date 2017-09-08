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

package org.cesecore.config;

import java.io.Serializable;
import java.util.Random;

import org.apache.log4j.Logger;

/**
 * Represents an individual RA CSS File
 * @version $Id$
 *
 */
public class RaCssInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaCssInfo.class);
    private static final Random random = new Random();
    
    private int cssId;
    private byte[] cssBytes;
    private String fileName;
    
    /**
     * Creates a RA CSS Info object to hold information and CSS data to be stored
     * in database for deployment on RA-web
     * @param cssBytes byte array of CSS file
     * @param fileName name of CSS file
     */
    public RaCssInfo(final byte[] cssBytes, String fileName) {
        this.cssId = random.nextInt();
        this.cssBytes = cssBytes;
        this.fileName = fileName;
    }
    
    /** @return unique id for RaCssInfo object*/
    public int getCssId() {
        return cssId;
    }
    
    /** @return byte array of CSS file*/
    public byte[] getCssBytes() {
        return cssBytes;
    }
    
    /** @param cssBytes of CSS file */
    public void setCssBytes(byte[] cssBytes) {
        this.cssBytes = cssBytes;
    }

    /** @return file name associated with CSS */
    public String getFileName() {
        return fileName;
    }

    /** @param fileName to be associated with CSS */
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    /** @return a human readable representation of the CSS */
    public String getReadable() {
        return new String(cssBytes);
    }
}
