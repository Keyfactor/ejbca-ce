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

package org.ejbca.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * A class to generate unique names.
 * This is to avoid name collisions in the system tests.
 */
public final class NameProvider {

    private static final Random RANDOM = new Random(System.currentTimeMillis());

    private String prefix;
    private int counter;
    private List<String> names;

    private static int getNextInt() {
        int modulus = 10_0000;
        int n = RANDOM.nextInt() % modulus;
        return n < 0 ? n + modulus : n;
    }

    public NameProvider(Class clazz) {
        String.format("%05d", RANDOM.nextInt()%100000);
        this.prefix = clazz.getSimpleName()+"_"+String.format("%05d", getNextInt());
        this.counter = 0;
        this.names = new ArrayList<>();
    }

    public String getNextName() {
        counter++;
        final var name = prefix + "_" + counter;
        names.add(name);
        return name;
    }

    public List<String> getNames() {
        return names;
    }

}
