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
package org.ejbca.ui.web.rest.api.io.response;

import org.cesecore.keys.keyimport.KeyImportFailure;

import java.util.List;

/**
 * Response for key import.
 */
public class KeyImportRestResponseV2 {
    private String message;

    private List<KeyImportFailure> keyImportFailures;

    public KeyImportRestResponseV2(List<KeyImportFailure> keyImportFailures, String message) {
        this.keyImportFailures = keyImportFailures;
        this.message = message;
    }

    public KeyImportRestResponseV2() {
        
    }

    public List<KeyImportFailure> getKeyImportFailures() {
        return this.keyImportFailures;
    }

    public String getMessage() {
        return this.message;
    }
    /**
     * Returns a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static KeyImportRestResponseBuilderV2 builder() {
        return new KeyImportRestResponseBuilderV2();
    }

    public static class KeyImportRestResponseBuilderV2 {
        private List<KeyImportFailure> keyImportFailures;
        
        public KeyImportRestResponseBuilderV2() {}

        public KeyImportRestResponseBuilderV2 setKeyImportFailures(final List<KeyImportFailure> keyImportFailures) {
            this.keyImportFailures = keyImportFailures;
            return this;
        }

        public KeyImportRestResponseV2 build() {
            final String message = keyImportFailures.isEmpty() ?
                    "All keystores are imported successfully. " :
                    keyImportFailures.size() + " keystores failed to import";

            return new KeyImportRestResponseV2(keyImportFailures, message);
        }
    }
    
    public KeyImportRestResponseConverterV2 convert() {
        return new KeyImportRestResponseConverterV2();
    }
    
    public static class KeyImportRestResponseConverterV2 {
        public KeyImportRestResponseConverterV2() {}
        
        public KeyImportRestResponseV2 toKeyImportRestResponse(List<KeyImportFailure> keyImportFailures) {
            return KeyImportRestResponseV2.builder().setKeyImportFailures(keyImportFailures).build();
        }
    }
}