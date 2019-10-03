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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang.builder.HashCodeBuilder;

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
        ACMECONFIG("acme-config"), CA("certification-authorities"), CRYPTOTOKEN("crypto-tokens"), PUBLISHER("publishers"),
        APPROVALPROFILE("approval-profiles"), CERTPROFILE("certificate-profiles"), EEPROFILE("end-entity-profiles"),
        SERVICE("services"), ROLE("admin-roles"), KEYBINDING("internal-key-bindings"), ADMINPREFS("admin-preferences"),
        OCSPCONFIG("ocsp-configuration"), PEERCONNECTOR("peer-connectors"), SCEPCONFIG("scep-config"), ESTCONFIG("est-config"),
        VALIDATOR("validators"), CTLOG("ct-logs"), EXTENDEDKEYUSAGE("extended-key-usage"), CERTEXTENSION("custom-certificate-extensions");
        // Unimplemented:
        //ENDENTITY, SYSCONFIG, CMPCONFIG, PEERCONFIG

        private final String subdirectory;

        private ItemType(final String subdirectory) {
            this.subdirectory = subdirectory;
        }

        public String getSubdirectory() { return subdirectory; }
    };
    
    public enum ImportMode {
        REPLACE,
        UPDATE,
        NO_OVERWRITE,
        DRY_RUN,
    }

    /** Identifies an object in EJBCA */
    public static final class ItemKey implements Comparable<ItemKey>, Serializable {
        private static final long serialVersionUID = 1L;
        private final ItemType type;
        private final String name;
        public ItemKey(final ItemType type, final String name) {
            this.type = type;
            this.name = name;
        }
        /** Returns the type, for example {@link ItemType#EEPROFILE} */
        public ItemType getType() { return type; }
        /** Returns the name of the object in EJBCA (for example End Entity Profile name) */
        public String getName() { return name; }

        @Override
        public boolean equals(final Object other) {
            if (other instanceof ItemKey) {
                return compareTo((ItemKey) other) == 0;
            } else {
                return false;
            }
        }

        @Override
        public int hashCode() {
            return new HashCodeBuilder().append(type).append(name).toHashCode();
        }

        @Override
        public int compareTo(final ItemKey o) {
            if (o == this) {
                return 0;
            } else if (type != o.type) {
                return type.ordinal() - o.type.ordinal();
            } else if (name == null) {
                return o.name == null ? 0 : -1;
            } else if (o.name == null) {
                return 1;
            } else {
                return name.compareTo(o.name);
            }
        }
    }

    private File location;
    private Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
    private Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
    private List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
    private List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
    private boolean ignoreErrors;
    private boolean ignoreWarnings;
    private ImportMode importMode;
    private Map<ItemKey, ImportMode> overwriteResolutions = new HashMap<>();
    private Map<ItemKey, String> passwords = new HashMap<>();
    private boolean initializeCas;
    private boolean exportDefaults;
    private boolean exportExternalCas;

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

    public void setIgnoreErrors(final boolean ignoreErrors) {
        this.ignoreErrors = ignoreErrors;
    }

    public boolean getIgnoreWarnings() {
        return ignoreWarnings;
    }

    public void setIgnoreWarnings(final boolean ignoreWarnings) {
        this.ignoreWarnings = ignoreWarnings;
    }

    public ImportMode getImportMode() {
        return importMode;
    }

    public void setImportMode(final ImportMode importMode) {
        this.importMode = importMode;
    }

    public void setOverwriteResolutions(final Map<ItemKey,ImportMode> overwriteResolutions) {
        this.overwriteResolutions = new HashMap<>(overwriteResolutions);
    }
    
    public Map<ItemKey,ImportMode> getOverwriteResolutions() {
        return Collections.unmodifiableMap(overwriteResolutions);
    }

    public void addOverwriteResolution(final ItemKey item, final ImportMode resolution) {
        overwriteResolutions.put(item, resolution);
    }
    
    public boolean getInitializeCas() {
        return initializeCas;
    }

    public void setInitializeCas(final boolean initializeCas) {
        this.initializeCas = initializeCas;
    }

    public boolean isExportDefaults() {
        return exportDefaults;
    }

    public void setExportDefaults(final boolean exportDefaults) {
        this.exportDefaults = exportDefaults;
    }

    public boolean isExportExternalCas() {
        return exportExternalCas;
    }

    public void setExportExternalCas(final boolean exportExternalCas) {
        this.exportExternalCas = exportExternalCas;
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

    public void putPassword(final ItemKey itemKey, final String password) {
        passwords.put(itemKey, password);
    }

    public Optional<String> getPasswordFor(final ItemKey itemKey) {
        return Optional.ofNullable(passwords.get(itemKey));
    }
}
