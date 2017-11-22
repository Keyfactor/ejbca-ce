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

import java.util.Collection;
import java.util.List;

import org.cesecore.profiles.Profile;

public interface CertificateProfileAwareValidator extends Profile {

    /** 
     * If the validator should apply to All certificate profiles. 
     * 
     * @return true or false.
     */
    boolean isAllCertificateProfileIds();

    /** 
     * Sets if validation should be performed for all certificate profile ids.
     * 
     * @param isAll, true if validation should be done for all certificate profiles.
     */
    void setAllCertificateProfileIds(boolean isAll);

    /** 
     * Gets a list of selected certificate profile ids. 
     * 
     * @return the list.
     */
    List<Integer> getCertificateProfileIds();

    /** 
     * Sets the selected certificate profile ids.
     * 
     * @param ids the collection of ids.
     */
    void setCertificateProfileIds(Collection<Integer> ids);
}
