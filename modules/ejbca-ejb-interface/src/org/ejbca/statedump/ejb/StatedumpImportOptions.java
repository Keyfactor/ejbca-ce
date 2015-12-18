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
import java.util.HashMap;
import java.util.Map;

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
    private boolean merge;
    private final Map<StatedumpObjectKey,StatedumpResolution> resolutions = new HashMap<>();
    private final Map<StatedumpObjectKey,String> passwords = new HashMap<>();
    
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
}
