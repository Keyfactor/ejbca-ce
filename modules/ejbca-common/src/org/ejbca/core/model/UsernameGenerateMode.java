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

package org.ejbca.core.model;

import java.util.Arrays;
import java.util.Optional;

public enum UsernameGenerateMode {

    /** Use a part of the DN as pase username */
    DN,
    /** Create a completely random username */
    RANDOM,
    /** use a fixed (set as dNGeneratorComponent) username */
    FIXED,
    /** Use the input as the base username */
    USERNAME;

    public static Optional<UsernameGenerateMode> fromString(String mode) {
        return Arrays.stream(UsernameGenerateMode.values())
                .filter(item -> item.name().equalsIgnoreCase(mode))
                .findFirst();
    }

}
