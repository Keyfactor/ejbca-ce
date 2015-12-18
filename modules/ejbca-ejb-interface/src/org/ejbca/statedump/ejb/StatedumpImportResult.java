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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Results of a dry-run of a statedump import
 * 
 * @version $Id$
 */
public final class StatedumpImportResult implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final List<StatedumpObjectKey> conflicts = new ArrayList<>();
    private final List<StatedumpObjectKey> passwordsNeeded = new ArrayList<>();
    private final Set<StatedumpObjectKey> existingNames = new HashSet<>();
    private final Set<StatedumpObjectKey> existingIds = new HashSet<>();
    private final List<String> notices = new ArrayList<>();
    private long objectCount = 0;
    
    /**
     * Returns a list of items that conflict with an existing item, because it has the same name or id.
     */
    public List<StatedumpObjectKey> getConflicts() {
        return Collections.unmodifiableList(conflicts);
    }
    
    /** Internal method, used during statedump imports. Can't be package internal since it's called from the bean */
    public void _addConflict(final StatedumpObjectKey key) {
        conflicts.add(key);
    }
    
    /**
     * Returns a list of items that might need a password when imported (e.g. crypto tokens and end entities)
     */
    public List<StatedumpObjectKey> getPasswordsNeeded() {
        return Collections.unmodifiableList(passwordsNeeded);
    }
    
    /** Internal method, used during statedump imports. Can't be package internal since it's called from the bean */
    public void _addPasswordNeeded(final StatedumpObjectKey key) {
        passwordsNeeded.add(key);
    }

    /**
     * Check whether the id of an object is already in use.
     */
    public boolean hasExistingId(final StatedumpObjectKey key) {
        return existingIds.contains(key);
    }
    
    /** Internal method, used during statedump imports. Can't be package internal since it's called from the bean */
    public void _addExistingId(final StatedumpObjectKey key) {
        existingIds.add(key);
    }
    
    /**
     * Check whether the name of an object is already in use.
     */
    public boolean hasExistingName(final StatedumpObjectKey key) {
        return existingNames.contains(key);
    }
    
    /** Internal method, used during statedump imports. Can't be package internal since it's called from the bean */
    public void _addExistingName(final StatedumpObjectKey key) {
        existingNames.add(key);
    }
    
    public long getObjectCount() {
        return objectCount;
    }
    
    /** Internal method, used during statedump imports. Can't be package internal since it's called from the bean */
    public void _addToObjectCount() {
        objectCount += 1;
    }

    public void _addNotice(final String msg) {
        notices.add(msg);
    }
    
    /** Returns a list of info log messages that where generated during the import */
    public List<String> getNotices() {
        return notices;
    }

}
