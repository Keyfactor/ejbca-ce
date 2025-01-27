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

import com.fasterxml.jackson.annotation.JsonInclude;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.ejbca.core.model.era.RaKeyImportResponseV2;

import java.util.List;

/**
 * Response for key import.
 */
public class KeyImportRestResponseV2 {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String generalErrorMessage;
    private List<KeyImportFailure> keyImportFailures;

    public KeyImportRestResponseV2(String generalErrorMessage, List<KeyImportFailure> keyImportFailures) {
        this.generalErrorMessage = generalErrorMessage;
        this.keyImportFailures = keyImportFailures;
    }

    public KeyImportRestResponseV2() {
        
    }

    public String getGeneralErrorMessage() {
        return generalErrorMessage;
    }

    public List<KeyImportFailure> getKeyImportFailures() {
        return keyImportFailures;
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
        private String generalErrorMessage;
        private List<KeyImportFailure> keyImportFailures;
        
        public KeyImportRestResponseBuilderV2() {}

        public KeyImportRestResponseBuilderV2 setGeneralErrorMessage(final String generalErrorMessage) {
            this.generalErrorMessage = generalErrorMessage;
            return this;
        }

        public KeyImportRestResponseBuilderV2 setKeyImportFailures(final List<KeyImportFailure> keyImportFailures) {
            this.keyImportFailures = keyImportFailures;
            return this;
        }

        public KeyImportRestResponseV2 build() {
            return new KeyImportRestResponseV2(generalErrorMessage, keyImportFailures);
        }
    }
    
    public KeyImportRestResponseConverterV2 convert() {
        return new KeyImportRestResponseConverterV2();
    }
    
    public static class KeyImportRestResponseConverterV2 {
        public KeyImportRestResponseConverterV2() {}
        
        public KeyImportRestResponseV2 toKeyImportRestResponse(RaKeyImportResponseV2 raResponse) {
            return KeyImportRestResponseV2.builder().setKeyImportFailures(raResponse.getFailedKeys())
                    .setGeneralErrorMessage(raResponse.getGeneralErrorMessage())
                    .build();
        }
    }
}