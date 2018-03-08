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
package org.ejbca.configdump;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Data class containing settings for configuration dump.
 * Probably better to use a builder pattern here.
 * 
 * @version $Id$
 *
 */
public class ConfigDumpSetting implements Serializable {

    private static final long serialVersionUID = 1L;

    public enum ItemType {
        CA, CRYPTOTOKEN, PUBLISHER, APPROVALPROFILE, CERTPROFILE, EEPROFILE, SERVICE, ROLE, KEYBINDING, 
        ENDENTITY, SYSCONFIG, ADMINPREFS, CMPCONFIG, OCSPCONFIG, PEERCONNECTOR, PEERCONFIG, SCEPCONFIG, ESTCONFIG,
        VALIDATOR, CTLOG, EXTENDEDKEYUSAGE, CERTEXTENSION
    };

    private File location;
    private Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
    private Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
    private List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
    private List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
    private boolean ignoreErrors;

    public List<ConfigdumpPattern> getIncludedAnyType() {
        return includedAnyType;
    }

    public void setIncludedAnyType(List<ConfigdumpPattern> includedAnyType) {
        this.includedAnyType = includedAnyType;
    }

    public List<ConfigdumpPattern> getExcludedAnyType() {
        return excludedAnyType;
    }

    public void setExcludedAnyType(List<ConfigdumpPattern> excludedAnyType) {
        this.excludedAnyType = excludedAnyType;
    }

    public File getLocation() {
        return location;
    }

    public void setLocation(File location) {
        this.location = location;
    }

    public void setIncluded(Map<ItemType, List<ConfigdumpPattern>> included) {
        this.included = included;
    }

    public void setExcluded(Map<ItemType, List<ConfigdumpPattern>> excluded) {
        this.excluded = excluded;
    }

    public Map<ItemType, List<ConfigdumpPattern>> getIncluded() {
        return included;
    }

    public Map<ItemType, List<ConfigdumpPattern>> getExcluded() {
        return excluded;
    }
    
    public boolean getIgnoreErrors() {
        return ignoreErrors;
    }

    public ConfigDumpSetting(final File location, final Map<ItemType, List<ConfigdumpPattern>> included, final Map<ItemType, List<ConfigdumpPattern>> excluded,
            final List<ConfigdumpPattern> includedAnyType, final List<ConfigdumpPattern> excludedAnyType, final boolean ignoreErrors) {
        this.location = location;
        this.included = included;
        this.excluded = excluded;
        this.includedAnyType = includedAnyType;
        this.excludedAnyType = excludedAnyType;
        this.ignoreErrors = ignoreErrors;
    }

    public boolean isIncluded(final ItemType type, final String nameStr) {
        
        final List<ConfigdumpPattern> includeList = included.get(type);
        final List<ConfigdumpPattern> excludeList = excluded.get(type);
        final String name = (nameStr != null ? nameStr.toLowerCase() : "");

        if (includeList != null) {
            for (ConfigdumpPattern p : includeList) {
                if (p.matches(name)) {
                    return true;
                }
            }
            return false;
        }

        if (!includedAnyType.isEmpty()) {
            for (ConfigdumpPattern p : includedAnyType) {
                if (p.matches(name)) {
                    return true;
                }
            }
            return false;
        }

        if (excludeList != null) {
            for (ConfigdumpPattern p : excludeList) {
                if (p.matches(name)) {
                    return false;
                }
            }
        }

        for (ConfigdumpPattern p : excludedAnyType) {
            if (p.matches(name)) {
                return false;
            }
        }

        // Didn't match anything. Default is to include.
        return true;
    }
    
}
