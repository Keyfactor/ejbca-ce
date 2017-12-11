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

import java.util.List;

/**
 * Type for phased validator (a validator bound to a defined phased of the certificate issuance process, #see  ).
 * 
 * @version $Id: PhasedValidator.java 26390 2017-12-11 07:20:58Z anjakobs $
 *
 */
public interface PhasedValidator {

    /**
     * Gets the list of applicable certificate issuance process phase indices ({@link ValidatorPhase}).
     * @return the list of certificate issuance process phase index.
     */
    List<Integer> getApplicablePhases();
    
    /**
     * Gets the certificate process phase index ({@link ValidatorPhase}).
     * @return the index.
     */
    int getPhase();
    
    /**
     * Sets the certificate process phase index ({@link ValidatorPhase}).
     * @param index the index.
     */
    void setPhase(int index);
}
