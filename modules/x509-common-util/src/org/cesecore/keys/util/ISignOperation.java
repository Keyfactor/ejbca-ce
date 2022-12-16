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
package org.cesecore.keys.util;

import java.security.Provider;
import java.util.List;

/**
 * An object of a class implementing this interface must be constructed
 * before using {@link SignWithWorkingAlgorithm}.
 * @version $Id$
 * 
 */
public interface ISignOperation {
    /**
     * This method must implement implement a task that is signing something.
     * It is used when there is no requirement on which signing algorithm to
     * use. The algorithm is chosen from a list of algorithms. The first time
     * the method is called we have to find an algorithm that is working for
     * the used provider (HSM). This is achieved by trying algorithms in the list
     * until a working one is found.
     * After this method has been successfully called succeeding calls will use
     * the algorithm that worked.
     * Call {@link SignWithWorkingAlgorithm#doSignTask(List, Provider, ISignOperation)}
     * when {@link #taskWithSigning(String, Provider)} should be executed.
     * @param signAlgorithm
     * @param provider
     * @throws TaskWithSigningException thrown if the signing can not be done.
     */
    void taskWithSigning(String signAlgorithm, Provider provider) throws TaskWithSigningException;
}
