/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.cli.infrastructure.parameter;

import java.util.HashMap;
import java.util.Map;

/**
 * A wrapper for the standard java HashMap. Restricted functionality, with some added extras. 
 * 
 * @version $Id$
 *
 */
public final class ParameterContainer {

    Map<String, ParameterInformation> parameters = new HashMap<String, ParameterInformation>();

    public ParameterContainer() {

    }

    /**
     * Copy constructor
     * 
     * @param parameterContainer
     */
    public ParameterContainer(final ParameterContainer parameterContainer) {
        this.parameters = new HashMap<String, ParameterContainer.ParameterInformation>(parameterContainer.parameters);
    }

    /** Returns parameter value, or null if parameter does not exist
     * 
     * @param key
     * @return parameter value, or null if parameter was not set
     */
    public String get(String key) {
        if (parameters.containsKey(key)) {
            return parameters.get(key).getValue();
        } else {
            return null;
        }
    }
    
    public boolean isStandalone(String key) {
        if (parameters.containsKey(key)) {
            return false;
        } else {
            return parameters.get(key).isStandalone();
        }
    }
    
    public void remove(String key) {
        parameters.remove(key);
    }

    public void put(String key, String value, boolean isStandalone) {
        parameters.put(key, new ParameterInformation(value, isStandalone));
    }

    public boolean containsKey(String key) {
        return parameters.containsKey(key);
    }

    private static final class ParameterInformation {
        private final String value;
        private final boolean isStandalone;

        private ParameterInformation(final String value, final boolean isStandalone) {
            this.value = value;
            this.isStandalone = isStandalone;
        }

        public boolean isStandalone() {
            return isStandalone;
        }

        public String getValue() {
            return value;
        }
    }
}
