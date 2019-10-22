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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang.builder.HashCodeBuilder;

import org.apache.commons.lang.StringUtils;

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

        ACMECONFIG("acme-config", "ACMECONFIG"),
        CA("certification-authorities", "CA"),
        CRYPTOTOKEN("crypto-tokens", "CRYPTOTOKEN"),
        PUBLISHER("publishers", "PUBLISHER"),
        APPROVALPROFILE("approval-profiles", "Approval Profile"),
        CERTPROFILE("certificate-profiles", "CERTPROFILE"),
        EEPROFILE("end-entity-profiles", "EEPROFILE"),
        SERVICE("services", "Services"),
        ROLE("admin-roles", "ROLE"),
        KEYBINDING("internal-key-bindings", "KEYBINDING"),
        ADMINPREFS("admin-preferences", "Admin Preference"),
        OCSPCONFIG("ocsp-configuration", "OCSP Configuration"),
        PEERCONNECTOR("peer-connectors", "Peer Connector"),
        SCEPCONFIG("scep-config", "SCEPCONFIG"),
        ESTCONFIG("est-config", "ESTCONFIG"),
        VALIDATOR("validators", "Validator"),
        CTLOG("ct-logs", "CT Log"),
        EXTENDEDKEYUSAGE("extended-key-usage", "EXTENDEDKEYUSAGE"),
        CERTEXTENSION("custom-certificate-extensions", "CERTEXTENSION");
        // Unimplemented:
        // ENDENTITY, SYSCONFIG, CMPCONFIG, PEERCONFIG

        private final String subdirectory;
        private final String name;

        ItemType(final String subdirectory, String name) {
            this.subdirectory = subdirectory;
            this.name = name;
        }

        public String getSubdirectory() { return subdirectory; }

        public String getName() {
            return name;
        }
    }

    public enum ProcessingMode {
        DRY_RUN,            // Process without persistence
        RUN                 // Process with persistence
    }

    public enum NonInteractiveMode {
        NONE,
        ABORT,            
        CONTINUE;
        
        public static NonInteractiveMode parseNonInteractiveMode(final String option) throws ParseException {
            if (option == null) {
                return NONE;
            }
            switch (StringUtils.lowerCase(option, Locale.ROOT)) {
                case "abort":
                    return ABORT;
                case "continue":
                    return CONTINUE;
                default:
                    throw new ParseException("Invalid non-interactive mode '" + option + "'", 0);
            }
        }
    }
        
    public enum OverwriteMode {
        NONE,
        UPDATE,
        SKIP;

        public static OverwriteMode parseOverwriteMode(final String option) throws ParseException {
            if (option == null) {
                return null; // = use default
            }
            switch (StringUtils.lowerCase(option, Locale.ROOT)) {
                case "skip":
                    return SKIP;
                case "update":
                    return UPDATE;
                default:
                    throw new ParseException("Invalid overwrite mode '" + option + "'", 0);
            }
        }
    }

    public enum ResolveReferenceMode {

        NO_RESOLUTION_SET,      // Doesn't have a reference problem
        USE_DEFAULT,            // Try to use default
        SKIP;                   // Exclude from import

        public static ResolveReferenceMode parseResolveReferenceMode(final String option) throws ParseException {
            if (option == null) {
                return null; // = use default
            }
            switch (StringUtils.lowerCase(option, Locale.ROOT)) {
                case "skip":
                    return SKIP;
                case "default":
                    return USE_DEFAULT;
                default:
                    throw new ParseException("Invalid resolve-reference mode '" + option + "'", 0);
            }
        }
    }

    public enum ItemProblem {
        NO_PROBLEM,
        EXISTING,
        MISSING_REFERENCE,
        EXISTING_AND_MISSING_REFERENCE
    }

    private File location;
    private Map<ItemType, List<ConfigdumpPattern>> included = new HashMap<>();
    private Map<ItemType, List<ConfigdumpPattern>> excluded = new HashMap<>();
    private List<ConfigdumpPattern> includedAnyType = new ArrayList<>();
    private List<ConfigdumpPattern> excludedAnyType = new ArrayList<>();
    private Set<String> overwriteExceptions = new HashSet<>();
    private boolean ignoreErrors;
    private boolean ignoreWarnings;
    private NonInteractiveMode nonInteractiveMode = NonInteractiveMode.NONE;
    private ProcessingMode processingMode;
    private OverwriteMode overwriteMode = OverwriteMode.NONE;
    private ResolveReferenceMode resolveReferenceMode = ResolveReferenceMode.NO_RESOLUTION_SET;
    private Map<ConfigdumpItem, OverwriteMode> overwriteResolutions = new HashMap<>();
    private Map<ConfigdumpItem, ResolveReferenceMode> resolveReferenceModeResolutions = new HashMap<>();
    private Map<ConfigdumpItem, String> passwords = new HashMap<>();
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

    public Set<String> getOverwriteExceptions() {
        return overwriteExceptions;
    }

    public void setOverwriteExceptions(Set<String> overwriteExceptions) {
        this.overwriteExceptions = overwriteExceptions;
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
    
    public NonInteractiveMode getNonInteractiveMode() {
        return nonInteractiveMode;
    }

    public void setNonInteractiveMode(final NonInteractiveMode nonInteractiveMode) {
        this.nonInteractiveMode = nonInteractiveMode;
    }
        
    public ProcessingMode getProcessingMode() {
        return processingMode;
    }

    public void setProcessingMode(ProcessingMode processingMode) {
        this.processingMode = processingMode;
    }

    public OverwriteMode getOverwriteMode() {
        return overwriteMode;
    }

    public void setOverwriteMode(final OverwriteMode overwriteMode) {
        this.overwriteMode = overwriteMode;
    }

    public ResolveReferenceMode getResolveReferenceMode() {
        return resolveReferenceMode;
    }

    public void setResolveReferenceMode(ResolveReferenceMode resolveReferenceMode) {
        this.resolveReferenceMode = resolveReferenceMode;
    }

    public void setOverwriteResolutions(final Map<ConfigdumpItem, OverwriteMode> overwriteResolutions) {
        this.overwriteResolutions = new HashMap<>(overwriteResolutions);
    }

    public Map<ConfigdumpItem, OverwriteMode> getOverwriteResolutions() {
        return Collections.unmodifiableMap(overwriteResolutions);
    }

    public void addOverwriteResolution(final ConfigdumpItem item, final OverwriteMode resolution) {
        overwriteResolutions.put(item, resolution);
    }

    public Map<ConfigdumpItem, ResolveReferenceMode> getReferenceModeResolutions() {
        return Collections.unmodifiableMap(resolveReferenceModeResolutions);
    }

    public void addResolveReferenceModeResolution(final ConfigdumpItem item, final ResolveReferenceMode resolveReferenceMode) {
        resolveReferenceModeResolutions.put(item, resolveReferenceMode);
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

    public void putPassword(final ConfigdumpItem configdumpItem, final String password) {
        passwords.put(configdumpItem, password);
    }

    public Optional<String> getPasswordFor(final ConfigdumpItem configdumpItem) {
        return Optional.ofNullable(passwords.get(configdumpItem));
    }
}
