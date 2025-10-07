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

package org.cesecore.dto;

import java.io.Serializable;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Stream;

public enum TokenMatchOperator implements Serializable, Supplier<Integer> {

    TYPE_UNUSED(0),
    TYPE_EQUALCASE(1000),
    /** Case insensitive. Can be used for textual match values, e.g. a Common Name. Do <b>NOT</b> use with serial numbers (a change since 6.8.0)  */
    TYPE_EQUALCASEINS(1001);


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
