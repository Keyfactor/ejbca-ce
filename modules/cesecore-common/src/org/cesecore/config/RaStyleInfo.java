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

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import java.io.Serializable;
import java.util.*;

/**
 * Represents an individual RA Style Archive. May or may not contain logo files, mulitple CSS files
 * and identifiers.
 *
 * @version $Id$
 */
public class RaStyleInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Random random = new Random();
    
    private int archiveId;
    private Map<String, RaCssInfo> raCssInfos;
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
    public RaStyleInfo(String fileName, Map<String, RaCssInfo> raCssInfos, final byte[] logoBytes, String logoName) {
        this.archiveId = random.nextInt();
        if (raCssInfos == null) {
            this.raCssInfos = new HashMap<>();
        } else {
            this.raCssInfos = raCssInfos;
        }
        this.logoBytes = logoBytes;
        this.archiveName = fileName;
        this.logoName = logoName;
    }
    
    public static class RaCssInfo implements Serializable {
        private static final long serialVersionUID = -7528899224548330073L;

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

    /** Should not be used normally! */
    public void setArchiveId(int archiveId) {
        this.archiveId = archiveId;
    }
    
    /** @param raCssInfo CSS info added to archive */
    public void addRaCssInfo(RaCssInfo raCssInfo) {
        this.raCssInfos.put(raCssInfo.getCssName(), raCssInfo);
    }
    
    /** @return Map of all CSS infos in archive*/
    public Map<String, RaCssInfo> getRaCssInfos() {
        return raCssInfos;
    }
    
    /** @return List of all CSS infos in the archive*/
    public List<RaCssInfo> getRaCssValues() {
        return new ArrayList<>(getRaCssInfos().values());
    }
    
    /** @param raCssInfos sets a list of CSS infos to archive */
    public void setRaCssInfos(HashMap<String, RaCssInfo> raCssInfos) {
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
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        RaStyleInfo other = (RaStyleInfo) obj;
        if (archiveId != other.archiveId) {
            return false;
        }
        return true;
    }

    public Map<String, Object> getAsMap() {
        final Map<String, Object> map = new LinkedHashMap<>();
        final Map<String, Object> hashes = new LinkedHashMap<>();
        final Keccak.Digest256 sha3 = new Keccak.Digest256();
        final byte[] logoHash = sha3.digest(logoBytes);
        for (RaCssInfo raCssInfo : raCssInfos.values()) {
            sha3.update(raCssInfo.getCssBytes());
        }
        final byte[] cssHash = sha3.digest();
        hashes.put("algorithm", sha3.getAlgorithm());
        hashes.put("css_hash", Hex.encodeHexString(cssHash));
        hashes.put("logo_hash", Hex.encodeHexString(logoHash));
        map.put("archive_name", archiveName);
        map.put("css_files", Arrays.asList(raCssInfos.keySet()));
        map.put("logo_name", logoName);
        map.put("logo_type", logoContentType);
        map.put("hashes", hashes);
        return map;
    }

    @Override
    public String toString() {
        return getAsMap().toString();
    }
}
