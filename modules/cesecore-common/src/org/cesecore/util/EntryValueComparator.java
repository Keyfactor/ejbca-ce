/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.io.Serializable;
import java.util.Comparator;
import java.util.Map.Entry;

/**
 * Compares the values in entries with a given comparator (e.g. AsStringComparator)
 * @version $Id$
 */
public final class EntryValueComparator<T> implements Comparator<Entry<?,? extends T>>, Serializable {

    private static final long serialVersionUID = 1L;
    private final Comparator<T> valueComparator;
    
    public EntryValueComparator(final Comparator<T> valueComparator) {
        this.valueComparator = valueComparator;
    }

    @Override
    public int compare(final Entry<?,? extends T> o1, final Entry<?,? extends T> o2) {
        return valueComparator.compare(o1.getValue(), o2.getValue());
    }
}
