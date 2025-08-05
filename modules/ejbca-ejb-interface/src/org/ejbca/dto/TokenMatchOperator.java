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

package org.ejbca.dto;

import java.io.Serializable;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Stream;

public enum TokenMatchOperator implements Serializable, Supplier<Integer> {

    TYPE_UNUSED(0),
    TYPE_EQUALCASE(1000),
    /** Case insensitive. Can be used for textual match values, e.g. a Common Name. Do <b>NOT</b> use with serial numbers (a change since 6.8.0)  */
    TYPE_EQUALCASEINS(1001),
    @Deprecated
    TYPE_NOT_EQUALCASE(1002),
    @Deprecated
    TYPE_NOT_EQUALCASEINS(1003),
    @Deprecated
    TYPE_NONE(1999),
    /** Type 2000-2005 are old types used from before EJBCA 4, we must expect to find these in the database in old installations, even though we don't want to use them.
     * These have no meaning whatsoever in newer installations of EJBCA, and can safely be removed from the database if found (unless we need to run an old installation in parallel). */
    @Deprecated
    SPECIALADMIN_PUBLICWEBUSER(2000),
    @Deprecated
    SPECIALADMIN_CACOMMANDLINEADMIN(2001),
    @Deprecated
    SPECIALADMIN_RAADMIN(2002),
    @Deprecated
    SPECIALADMIN_BATCHCOMMANDLINEADMIN(2003),
    @Deprecated
    SPECIALADMIN_INTERNALUSER(2004),
    @Deprecated
    SPECIALADMIN_NOUSER(2005);

    private final Integer value;

    TokenMatchOperator(int value) {
        this.value = value;
    }

    @Override
    public Integer get() {
        return value;
    }

    public static TokenMatchOperator valueOf(Integer value) {
        if (value == null) {
            return null;
        }
        return Stream.of(values())
                .filter(e -> Objects.equals(e.get(), value))
                .findFirst()
                .orElse(null);
    }

}
