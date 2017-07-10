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
package org.cesecore.keys.validation;

import java.io.Serializable;
import java.util.List;

/**
 * POJO containing the results of importing a zip file of key validators.
 * 
 * @version $Id$
 *
 */
public class ValidatorImportResult implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final List<Validator> importedValidators;
    private final List<String> ignoredValidators;

    public ValidatorImportResult(List<Validator> importedValidators, List<String> ignoredValidators) {
        super();
        this.importedValidators = importedValidators;
        this.ignoredValidators = ignoredValidators;
    }
    
    public List<Validator> getImportedValidators() {
        return importedValidators;
    }

    public List<String> getIgnoredValidators() {
        return ignoredValidators;
    }
    
}
