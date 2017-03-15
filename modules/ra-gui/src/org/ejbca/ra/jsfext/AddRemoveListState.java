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
 * Backing state for the addremovelist.xhtml component, which is a list with an "Enabled" and an "Available" list that items may be moved between.
 * 
 * The getEnabledItems() and getItemStates() methods returns the enabled items.
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
    
    /**
     * Adds an item to be listed in the component
     * @param value Item value. Not displayed to the user, but will be visible in the HTML source code.
     * @param label Label to show in the lists in the user interface
     * @param enabled If the item is enabled.
     */
    public void addListItem(final T value, final String label, final boolean enabled) {
        final SelectItem item = new SelectItem(value, label);
        if (enabled) {
            enabledSelectItems.add(item);
        } else {
            availableSelectItems.add(item);
        }
    }

    /** Internal method that returns the currently selected items in the enabled list. These can be removed with the "Remove" button. */
    public List<T> getSelectedInEnabledList() { return selectedInEnabledList; }
    public void setSelectedInEnabledList(final List<T> selectedInEnabledList) { this.selectedInEnabledList = selectedInEnabledList; }
    /** Internal method that returns the currently selected items in the available list. These can be added with the "Add" button. */
    public List<T> getSelectedInAvailableList() { return selectedInAvailableList; }
    public void setSelectedInAvailableList(final List<T> selectedInAvailableList) { this.selectedInAvailableList = selectedInAvailableList; }
    /** Internal method that returns the items that are currently enabled, that the user can remove */
    public List<SelectItem> getEnabledSelectItems() { return enabledSelectItems; }
    /** Internal method that returns the items that are currently available but not enabled, that the user can add */
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
    
    /** Internal method that's called when the user clicks the "Add" button */
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
    
    /** Internal method that's called when the user clicks the "Remove" button */
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
    
    /** Internal method that's called when the user clicks the "Add all" button */
    public void addAll() {
        enabledSelectItems.addAll(availableSelectItems);
        selectedInAvailableList.clear();
        availableSelectItems.clear();
    }
    
    /** Internal method that's called when the user clicks the "Remove all" button */
    public void removeAll() {
        availableSelectItems.addAll(enabledSelectItems);
        selectedInEnabledList.clear();
        enabledSelectItems.clear();
    }
}
