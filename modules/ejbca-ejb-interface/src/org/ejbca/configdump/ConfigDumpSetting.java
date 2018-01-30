/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.configdump;

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
        CA, CRYPTOTOKEN, PUBLISHER, APPROVALPROFILE, CERTPROFILE, EEPROFILE, SERVICE, ROLE, KEYBINDING, ENDENTITY, SYSCONFIG, ADMINPREFS, CMPCONFIG, OCSPCONFIG, PEERCONNECTOR, PEERCONFIG
    };

    private String location;
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

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
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

    public ConfigDumpSetting(final String location, final Map<ItemType, List<ConfigdumpPattern>> included, final Map<ItemType, List<ConfigdumpPattern>> excluded,
            final List<ConfigdumpPattern> includedAnyType, final List<ConfigdumpPattern> excludedAnyType, final boolean ignoreErrors) {
        this.location = location;
        this.included = included;
        this.excluded = excluded;
        this.includedAnyType = includedAnyType;
        this.excludedAnyType = excludedAnyType;
        this.ignoreErrors = ignoreErrors;
    }
}
