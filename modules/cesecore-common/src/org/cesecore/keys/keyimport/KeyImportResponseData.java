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
package org.cesecore.keys.keyimport;

import java.io.Serializable;
import java.util.List;

/**
 * Holds data which can be output in the key import response.
 */
public class KeyImportResponseData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String generalErrorMessage;
    private List<KeyImportFailure> failures;

    public KeyImportResponseData() {

    }

    public KeyImportResponseData(String generalErrorMessage, List<KeyImportFailure> failures) {
        this.generalErrorMessage = generalErrorMessage;
        this.failures = failures;
    }

    public List<KeyImportFailure> getFailures() {
        return failures;
    }

    public void setFailures(List<KeyImportFailure> failures) {
        this.failures = failures;
    }

    public String getGeneralErrorMessage() {
        return generalErrorMessage;
    }

    public void setGeneralErrorMessage(String generalErrorMessage) {
        this.generalErrorMessage = generalErrorMessage;
    }
}
