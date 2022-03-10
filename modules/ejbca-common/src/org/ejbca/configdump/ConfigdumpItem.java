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

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.cesecore.util.Named;
import org.ejbca.configdump.ConfigdumpSetting.ItemProblem;
import org.ejbca.configdump.ConfigdumpSetting.ItemType;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 *
 * A ConfigdumpItem
 *
 * @version $Id$
 */
public class ConfigdumpItem<T> implements Comparable<ConfigdumpItem<?>>, Serializable {
    private static final long serialVersionUID = 1L;

    private final String name;
    private final ItemType type;

    // Problems enum: NO_PROBLEM, EXISTING, MISSING_REFERENCE, EXISTING_AND_MISSING_REFERENCE
    private ItemProblem problem;
    private Integer id;
    //is a reference to an EJBCA item. The item can be in the database or in a YAML dump.
    private T dumpObject;

    public ConfigdumpItem(final String name, final ItemType type, final Integer id, final T dumpObject) {
        this.name = name;
        this.type = type;
        this.problem = ItemProblem.NO_PROBLEM;
        this.id = id;
        this.dumpObject = dumpObject;
    }

    /** Returns the type, for example {@link ItemType#EEPROFILE} */
    public ItemType getType() { return type; }

    /** Returns the name of the object in EJBCA (for example End Entity Profile name) */
    public String getName() { return name; }

    /** Returns the database ID of the EJBCA item. */
    public Integer getId() { return id; }
    public void setId(final int id) { this.id = id; }
    /** Return the EJBCA object loaded from database. May be null, for example when a CrudItem is created from an name-to-id map. */
    public T getDumpObject() { return dumpObject; }
    public void setDumpObject(final T dumpObject) { this.dumpObject = dumpObject; }

    public ItemProblem getProblem() {
        return problem;
    }

    public void setProblem(ItemProblem problem) {
        this.problem = problem;
    }

    /** Creates a list of ConfigdumpItem with the names given in the parameter */
    public static <T> List<ConfigdumpItem<T>> fromNameList(final List<String> names, final ItemType type) {
        final List<ConfigdumpItem<T>> items = new ArrayList<>();
        for (final String name : names) {
            items.add(new ConfigdumpItem<>(name, type, null, null));
        }
        return items;
    }

    /**
     * Creates a list of CrudItems based on a name-to-id map
     * @param map name-to-id map
     * @param idBoundary IDs lower than this value are considered built-in items and are not exported. Set to -1 if not applicable.
     */
    public static <T> List<ConfigdumpItem<T>> fromIdNameMap(final Map<Integer, String> map, int idBoundary, ItemType type) {
        final List<ConfigdumpItem<T>> items = new ArrayList<>();
        for (final Map.Entry<Integer, String> entry : map.entrySet()) {
            final int id = entry.getKey();
            if (id < 0 || id > idBoundary) {
                items.add(new ConfigdumpItem<>(entry.getValue(), type, id, null));
            }
        }
        return items;
    }

    /** Creates a list of ConfigdumpItem from a list of EJBCA objects. The objects must have a getName / implement the {@link Named} interface. */
    public static <T extends Named> List<ConfigdumpItem<T>> fromObjectList(final List<T> namedObjects, ItemType type) {
        final List<ConfigdumpItem<T>> items = new ArrayList<>();
        for (final T obj : namedObjects) {
            items.add(new ConfigdumpItem<>(obj.getName(), type,null, obj));
        }
        return items;
    }

    /** Creates a list with a single CrudItem with the given name */
    public static <T> List<ConfigdumpItem<T>> singletonName(final String name, ItemType type) {
        return Collections.singletonList(new ConfigdumpItem<T>(name,  type,null, null));
    }

    @Override
    public boolean equals(final Object other) {
        return other instanceof ConfigdumpItem && compareTo((ConfigdumpItem<?>) other) == 0;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(type).append(name).toHashCode();
    }

    @Override
    public int compareTo(final ConfigdumpItem<?> o) {
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

    @Override
    public String toString() {
        return "[ConfigdumpItem: " + type + " " + name + " (" + id + ")]";
    }
}
