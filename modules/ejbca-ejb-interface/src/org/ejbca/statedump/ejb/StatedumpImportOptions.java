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
package org.ejbca.statedump.ejb;

import java.io.File;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

/**
 * Options for statedump import. What to overwrite or not overwrite is also set in the options.
 * 
 * The location option is mandatory.
 * 
 * @version $Id$
 */
public final class StatedumpImportOptions implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private File location;
    private File overridesFile;
    private boolean merge;
    private final Map<StatedumpObjectKey,StatedumpResolution> resolutions = new HashMap<>();
    private final Map<StatedumpObjectKey,String> passwords = new HashMap<>();
    private final List<StatedumpCAIdChange> caIdChanges = new ArrayList<>();
    private final Map<String,List<StatedumpOverride>> overrides = new HashMap<>();
    
    public StatedumpImportOptions() {
        // Does nothing
    }
    
    /** Sets the directory to import from. Should be an absolute path. */
    public void setLocation(final File location) {
        this.location = location;
    }
    
    public File getLocation() {
        return location;
    }
    
    /** Sets the file to read overrides from. By default, no overrides are read. */
    public void setOverridesFile(final File overridesFile) {
        this.overridesFile = overridesFile;
    }
    
    public File getOverridesFile() {
        return overridesFile;
    }
    
    public void setMergeCryptoTokens(final boolean merge) {
        this.merge = merge;
    }

    public boolean getMergeCryptoTokens() {
        return merge;
    }
    
    public void addConflictResolution(final StatedumpObjectKey key, final StatedumpResolution resolution) {
        resolutions.put(key, resolution);
    }
    
    /** Internal method, but EJBs can't call package internal methods, so it must be public */
    public StatedumpResolution _lookupConflictResolution(final StatedumpObjectKey key) {
        return resolutions.get(key);
    }
    
    public void addPassword(final StatedumpObjectKey key, final String password) {
        passwords.put(key, password);
    }
    
    /** Internal method, but EJBs can't call package internal methods, so it must be public */
    public String _lookupPassword(final StatedumpObjectKey key) {
        return passwords.get(key);
    }
    
    /**
     * Adds a translation of a CA Subject DN (and CA Id, since it's calculated from the Subject DN)
     * @param fromId CA Id from CA while it still has the old name.
     * @param toId New CA Id
     * @param toSubjectDN CA Subject DN of new CA
     */
    public void addCASubjectDNChange(final int fromId, final int toId, final String toSubjectDN) {
        caIdChanges.add(new StatedumpCAIdChange(fromId, toId, toSubjectDN));
    }
    
    /** Internal method, but EJBs can't call package internal methods, so it must be public */
    public List<StatedumpCAIdChange> _getCASubjectDNChanges() {
        return caIdChanges;
    }
    
    /**
     * Adds an override of a field. See StatedumpFieldOverrider
     */
    public void addOverride(final String[] key, final StatedumpOverride.Type type, final Object value) {
        final String keyStr = StringUtils.join(key, '.');
        List<StatedumpOverride> list = overrides.get(keyStr);
        if (list == null) {
            list = new ArrayList<>();
            overrides.put(keyStr, list);
        }
        list.add(new StatedumpOverride(type, value));
    }
    
    /** Internal method, but EJBs can't call package internal methods, so it must be public */
    public List<StatedumpOverride> _getOverrides(final String[] key) {
        final String keyStr = StringUtils.join(key, '.');
        return overrides.get(keyStr);
    }
}
