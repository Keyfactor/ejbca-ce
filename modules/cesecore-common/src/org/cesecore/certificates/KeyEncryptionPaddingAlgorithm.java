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

package org.cesecore.certificates;

public enum KeyEncryptionPaddingAlgorithm {
	PKCS_1_5("PKCS 1.5"),
	RSA_OAEP("RSA OAEP");

	public final String name;

	KeyEncryptionPaddingAlgorithm(String name) {
		this.name = name;
	}

}
