/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;

/**
 * An enum domain class representing all key generator sources like openSSL, openSSH, openVPN, etc.
 *
 * @version $Id: KeyGeneratorSources.java 22117 2017-04-01 12:12:00Z anjakobs $
 */
public enum KeyGeneratorSources {

    // @formatter:off
    UNKNOWN(0, "KEYGENERATORSOURCE_UNKNOWN"), OPEN_SSH(1, "KEYGENERATORSOURCE_OPENSSH"), OPEN_SSL(2, "KEYGENERATORSOURCE_OPENSSL"), OPEN_VPN(3,
            "KEYGENERATORSOURCE_OPENVPN");
    // @formatter:on

    /** The unique source index. */
    private int source;

    /** The resource key or label. */
    private String label;

    /**
     * Creates a new instance.
     * 
     * @param source source
     * @param label resource key or label.
     */
    private KeyGeneratorSources(final int source, final String label) {
        this.source = source;
        this.label = label;
    }

    /**
     * Gets the source index.
     * @return
     */
    public int getSource() {
        return source;
    }

    /**
     * Gets the resource key or label.
     * @return
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an integer list instance containing all sources.
     * @return the list.
     */
    public static final List<Integer> sources() {
        final List<Integer> result = new ArrayList<Integer>();
        for (KeyGeneratorSources source : values()) {
            result.add(source.getSource());
        }
        return result;
    }

    /**
     * Gets a string list instance containing all sources.
     * @return the list.
     */
    public static final List<String> sourcesAsString() {
        final List<String> result = new ArrayList<String>();
        for (KeyGeneratorSources source : values()) {
            result.add(Integer.toString(source.getSource()));
        }
        return result;
    }

    /**
     * Gets a String list containing all sources as String.
     * @return the list.
     */
    public static final String toStringList() {
        final StringBuilder result = new StringBuilder();
        for (KeyGeneratorSources item : values()) {
            if (result.length() > 0) {
                result.append(',');
            }
            result.append(item.getSource()).append(item.name());
        }
        return result.toString();
    }
}
