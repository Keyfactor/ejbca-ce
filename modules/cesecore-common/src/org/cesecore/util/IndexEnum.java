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

/**
 * An enum where each enum value has an "index" value, which is guaranteed to not change between versions
 * (unlike the ordinal() method which can change if enum values are added, removed or reordered).
 * <p>
 * Avoid building enums using this pattern, unless storage space is really a concern.
 * Please store the enum name as a string instead.
 * 
 * @version $Id$
 */
public interface IndexEnum {
    /** Returns a stable "index" of the enum value, which is guaranteed to not change with new versions (unlike {@link Enum#ordinal}). */
    int getIndex();
}
