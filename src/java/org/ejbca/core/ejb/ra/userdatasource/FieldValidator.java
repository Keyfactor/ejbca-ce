package org.ejbca.core.ejb.ra.userdatasource;

import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.dn.DnComponents;

/**
 * This class should be used to define rules to validate fields' values when adding and updating end entities.
 * Example: It is possible to ensure that the subject DN serial number is always a number of six digits, or should always end with the letter 'N',
 * otherwise a CustomFieldException should be thrown with a suitable error message that will appear on the GUI.
 * @author aveen
 *
 */
public class FieldValidator {
	
	public FieldValidator(){}
	
	public static void validate(UserDataVO userdata, int profileid, String profilename) throws CustomFieldException{}

}
