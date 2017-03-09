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
package org.ejbca.ra.jsfext;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.faces.model.SelectItem;

/**
 * Backing state for the addremovelist.xhtml component. The getEnabledItems() and getItemStates() methods returns the enabled items.
 * Note that the type in the generic parameter must implement the equals() method.
 * @version $Id$
 */
public final class AddRemoveListState<T extends Serializable> implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private List<T> selectedInEnabledList = new ArrayList<>();
    private List<T> selectedInAvailableList = new ArrayList<>();
    
    private final List<SelectItem> enabledSelectItems = new ArrayList<>();
    /** List of available items, excluding the enabled items */
    private final List<SelectItem> availableSelectItems = new ArrayList<>();

//    /**
//     * @param enabledList List of enabled items. Will be modified
//     * @param availableList List of available items. Will not be modified
//     */
//    public AddRemoveListState(final List<T> enabledList, final List<T> availableList) {
    
    public void addListItem(final T value, final String label, final boolean enabled) {
        final SelectItem item = new SelectItem(value, label);
        if (enabled) {
            enabledSelectItems.add(item);
        } else {
            availableSelectItems.add(item);
        }
    }

    public List<T> getSelectedInEnabledList() { return selectedInEnabledList; }
    public void setSelectedInEnabledList(final List<T> selectedInEnabledList) { this.selectedInEnabledList = selectedInEnabledList; }
    public List<T> getSelectedInAvailableList() { return selectedInAvailableList; }
    public void setSelectedInAvailableList(final List<T> selectedInAvailableList) { this.selectedInAvailableList = selectedInAvailableList; }
    public List<SelectItem> getEnabledSelectItems() { return enabledSelectItems; }
    public List<SelectItem> getAvailableSelectItems() { return availableSelectItems; }
    
    /** Returns the enabled items */
    @SuppressWarnings("unchecked")
    public List<T> getEnabledItems() {
        final List<T> enabled = new ArrayList<>();
        for (final SelectItem item : enabledSelectItems) {
            enabled.add((T)item.getValue());
        }
        return enabled;
    }
    
    /** Returns the enabled items */
    @SuppressWarnings("unchecked")
    public Map<T,Boolean> getItemStates() {
        final Map<T,Boolean> state = new HashMap<>();
        for (final SelectItem item : enabledSelectItems) {
            state.put((T)item.getValue(), true);
        }
        for (final SelectItem item : availableSelectItems) {
            state.put((T)item.getValue(), false);
        }
        return state;
    }
    
    public void add() {
        for (final T selected : selectedInAvailableList) {
            for (final Iterator<SelectItem> iter = availableSelectItems.iterator(); iter.hasNext(); ) {
                final SelectItem availableItem = iter.next();
                if (availableItem.getValue().equals(selected)) {
                    iter.remove();
                    enabledSelectItems.add(availableItem);
                }
            }
        }
        selectedInAvailableList.clear();
    }
    
    public void remove() {
        for (final T selected : selectedInEnabledList) {
            for (final Iterator<SelectItem> iter = enabledSelectItems.iterator(); iter.hasNext(); ) {
                final SelectItem enabledItem = iter.next();
                if (enabledItem.getValue().equals(selected)) {
                    iter.remove();
                    availableSelectItems.add(enabledItem);
                }
            }
        }
        selectedInEnabledList.clear();
    }
    
    public void addAll() {
        enabledSelectItems.addAll(availableSelectItems);
        selectedInAvailableList.clear();
        availableSelectItems.clear();
    }
    
    public void removeAll() {
        availableSelectItems.addAll(enabledSelectItems);
        selectedInEnabledList.clear();
        enabledSelectItems.clear();
    }
}
