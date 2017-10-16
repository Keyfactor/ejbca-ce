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
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.apache.log4j.Logger;

/**
 * Represents an individual RA Style Archive. May or may not contain logo files, mulitple CSS files
 * and identifiers. 
 * @version $Id$
 *
 */
public class RaStyleInfo implements Serializable {
    
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaStyleInfo.class);
    private static final Random random = new Random();
    
    private int archiveId;
    private List<RaCssInfo> raCssInfos;
    private byte[] logoBytes;
    private String logoName;
    private String logoContentType;
    private String archiveName;
    
    /**
     * Creates a RA CSS Info object to hold information and CSS data to be stored
     * in database for deployment on RA-web
     * @param fileName name of the archive
     * @param raCssInfos List of CSS info holders. May be null
     * @param logoBytes Byte array of custom logo. May be null
     * @param logoName Name of custom logo. May be null
     */
    public RaStyleInfo(String fileName, List<RaCssInfo> raCssInfos, final byte[] logoBytes, String logoName) {
        this.archiveId = random.nextInt();
        if (raCssInfos == null) {
            this.raCssInfos = new ArrayList<>();
        } else {
            this.raCssInfos = raCssInfos;
        }
        this.logoBytes = logoBytes;
        this.archiveName = fileName;
        this.logoName = logoName;
    }
    
    @SuppressWarnings("serial")
    public static class RaCssInfo implements Serializable {
        private byte[] cssBytes;
        private String cssName;
        
        public RaCssInfo(byte[] cssBytes, String cssName) {
            this.cssBytes = cssBytes;
            this.cssName = cssName;
        }
        
        public byte[] getCssBytes() {
            return cssBytes;
        }

        public void setCssBytes(byte[] cssBytes) {
            this.cssBytes = cssBytes;
        }

        public String getCssName() {
            return cssName;
        }

        public void setCssName(String cssName) {
            this.cssName = cssName;
        }
    }
    
    /** @return unique id for RaCssInfo object*/
    public int getArchiveId() {
        return archiveId;
    }
    
    /** @param raCssInfo CSS info added to archive */
    public void addRaCssInfo(RaCssInfo raCssInfo) {
        this.raCssInfos.add(raCssInfo);
    }
    
    /** @return List of all CSS infos in archive*/
    public List<RaCssInfo> getRaCssInfos() {
        return raCssInfos;
    }
    
    /** @param raCssInfos sets a list of CSS infos to archive */
    public void setRaCssInfos(List<RaCssInfo> raCssInfos) {
        this.raCssInfos = raCssInfos;
    }

    /** @return byte array of logo */
    public byte[] getLogoBytes() {
        return logoBytes;
    }
    
    /** @param logoBytes logoBytes of logo image*/
    public void setLogoBytes(byte[] logoBytes) {
        this.logoBytes = logoBytes;
    }
    
    /** @return file name associated with CSS */
    public String getArchiveName() {
        return archiveName;
    }

    /** @param fileName to be associated with CSS */
    public void setArchiveName(String fileName) {
        this.archiveName = fileName;
    }
    
    /** @return name of logo */
    public String getLogoName() {
        return logoName;
    }
    
    /** @param logoName sets logo name */
    public void setLogoName(String logoName) {
        this.logoName = logoName;
    }
    
    /** @return content type of logo, e.g 'image/png' */
    public String getLogoContentType() {
        return logoContentType;
    }
    
    /** @param logoContentType e.g 'image/png' */
    public void setLogoContentType(String logoContentType) {
        this.logoContentType = logoContentType;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + archiveId;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RaStyleInfo other = (RaStyleInfo) obj;
        if (archiveId != other.archiveId)
            return false;
        return true;
    }
    
}
