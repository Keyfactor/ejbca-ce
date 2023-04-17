/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys.token.pkcs11;

import java.io.File;

/**
 * Interface for the factory to create PKCS11SlotListWrapper classes that wraps C_GetSlotList calls to P11 to get information about slots/tokens and their labels
 * This interface is used through the UI both when using SunP11 and P11NG, to display slot labels.
 */
public interface PKCS11SlotListWrapperFactory {
    /** 
     * Gets the instance of PKCS11SlotListWrapper, of this specific type to use, for the specified PKCS#11 library (.so, .dll).
     * @param pkcs11Library the PKCS#11 library that we want to use to call C_GetSlotList
     */
    PKCS11SlotListWrapper getInstance(File pkcs11Library);
    
    /**
     * When there are multiple implementations of PKCS11SlotListWrapperFactory, this returns their, own specified, priority which one should be used.
     * 
     * @return a number where the highest numbered priority implementation should be used 
     */
    int getPriority();
    
}
