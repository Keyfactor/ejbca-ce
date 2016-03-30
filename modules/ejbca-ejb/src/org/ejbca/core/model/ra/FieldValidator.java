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

package org.ejbca.core.model.ra;

import org.cesecore.certificates.endentity.EndEntityInformation;


/**
 * This class should be used to define rules to validate fields' values when adding and updating end entities.
 * Example: It is possible to ensure that the subject DN serial number is always a number of six digits, or should always end with the letter 'N',
 * otherwise a CustomFieldException should be thrown with a suitable error message that will appear on the GUI.
 * 
 * @version $Id$ 
 *
 */
public class FieldValidator {
	
	public FieldValidator(){}

	/**
	 * The rules and regulations of the contents of End Entity fields should be implemented here.
	 * 
	 * @param userdata object containing all the possible fields of an end entity
	 * @param profileid of the end entity profile
	 * @param profilename of the end entity profile
	 * @throws CustomFieldException when the value of a field does not match a specific rule.
	 */
	public static void validate(EndEntityInformation userdata, int profileid, String profilename) throws CustomFieldException{}

}
