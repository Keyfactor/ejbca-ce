/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.resource;

import java.util.ArrayList;
import java.util.List;

import org.ejbca.configdump.ConfigdumpResult;

/**
 * Rest resource response to a configdump import or export.  Very similar to a {@link ConfigdumpResult}, which wasn't exactly right for the REST API.
 */
public class ConfigdumpResults {
    private boolean success = true;
    private List<String> errors = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();

    public ConfigdumpResults(List<String> reportedErrors, List<String> reportedWarnings) {
        success = false;
        this.setErrors(reportedErrors);
        this.setWarnings(reportedWarnings);
    }

    public ConfigdumpResults() {
        this.success = true;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    @Override
    public String toString() {
        return "ConfigdumpImportResults [success=" + success + ", errors=" + errors + ", warnings=" + warnings + "]";
    }

}
