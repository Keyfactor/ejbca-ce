/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;


/** This class only exists in order to avoid having static non-final variables in CertificateStoreSessionBean (not allowed according to EJB spec).
 * This class holds the variable isUniqueCertificateSerialNumberIndex, which is initialized by calling, once (or several times)
 * CertificateStoreSessionLocal.checkForUniqueCertificateSerialNumberIndex(). Actually calling this method only does something once, called several times does nothing
 * and does not change any values returned by isUniqueCertificateSerialNumberIndex().
 *  
 * @version $Id$
 */
public final class UniqueSernoHelper {

	static private Boolean isUniqueCertificateSerialNumberIndex = null;

	/** Don't create any of this */
	private UniqueSernoHelper() {};
	
	/** @return isUniqueCertificateSerialNumberIndex, can be null which should be interpreted as uninitialized */
	public static Boolean getIsUniqueCertificateSerialNumberIndex() {
        return isUniqueCertificateSerialNumberIndex;
    }

	/** Sets isUniqueCertificateSerialNumberIndex, can set to null which should be interpreted as uninitialized */
    public static void setIsUniqueCertificateSerialNumberIndex(Boolean isUniqueCertificateSerialNumberIndex) {
        UniqueSernoHelper.isUniqueCertificateSerialNumberIndex = isUniqueCertificateSerialNumberIndex;
    }	
}
