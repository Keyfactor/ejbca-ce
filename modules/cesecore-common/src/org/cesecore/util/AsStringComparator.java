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

/**
 * Compares objects with their string representation, by calling String.valueOf(x) on the compared objects.
 * @version $Id$
 */
public final class AsStringComparator implements Comparator<Object>, Serializable {
    
    private static final long serialVersionUID = 1L;

    @Override
    public int compare(final Object o1, final Object o2) {
        final String s1 = String.valueOf(o1);
        final String s2 = String.valueOf(o2);
        return s1.compareTo(s2);
    }
}
