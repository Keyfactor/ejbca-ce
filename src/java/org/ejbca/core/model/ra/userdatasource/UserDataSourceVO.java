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
package org.ejbca.core.model.ra.userdatasource;

import java.io.Serializable;
import java.util.Set;

import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * UserDataSourceVO is a value object returned from the fetch method
 * of a user data source.
 * 
 * Contains two things one is the UserDataVO and the other is
 * a set of contants indicating which fields that should be modifyable by the RA.
 * 
 *  
 * @author Philip Vendil
 * @version $Id$
 */
public class UserDataSourceVO implements Serializable {    

	/**
	 * Constants used in isModifyable sets.
	 */
    public static final int ISMODIFYABLE_USERNAME           = 101;
    public static final int ISMODIFYABLE_PASSWORD           = 102;
    public static final int ISMODIFYABLE_CAID               = 103;
    public static final int ISMODIFYABLE_EMAILDATA          = 104;
    public static final int ISMODIFYABLE_TYPE               = 105;
    public static final int ISMODIFYABLE_ENDENTITYPROFILE   = 106;
    public static final int ISMODIFYABLE_CERTIFICATEPROFILE = 107;
    public static final int ISMODIFYABLE_TOKENTYPE          = 108;
    public static final int ISMODIFYABLE_HARDTOKENISSUER    = 109;

    public static final int[] AVAILABLEMODIFYABLEFIELDS    = {
    	ISMODIFYABLE_USERNAME , ISMODIFYABLE_PASSWORD , ISMODIFYABLE_CAID , ISMODIFYABLE_EMAILDATA ,
    	ISMODIFYABLE_TYPE , ISMODIFYABLE_ENDENTITYPROFILE , ISMODIFYABLE_CERTIFICATEPROFILE , ISMODIFYABLE_TOKENTYPE , ISMODIFYABLE_HARDTOKENISSUER,
    	DNFieldExtractor.UID , DNFieldExtractor.CN , DNFieldExtractor.SN , 
    	DNFieldExtractor.GIVENNAME , DNFieldExtractor.INITIALS , DNFieldExtractor.SURNAME , DNFieldExtractor.T ,
    	DNFieldExtractor.OU , DNFieldExtractor.O , DNFieldExtractor.L , DNFieldExtractor.ST ,
    	DNFieldExtractor.DC , DNFieldExtractor.C , DNFieldExtractor.UNSTRUCTUREDADDRESS , DNFieldExtractor.UNSTRUCTUREDNAME ,
    	DNFieldExtractor.DNSNAME , DNFieldExtractor.IPADDRESS ,
    	DNFieldExtractor.DIRECTORYNAME, DNFieldExtractor.URI ,
    	DNFieldExtractor.UPN , DNFieldExtractor.GUID , DNFieldExtractor.KRB5PRINCIPAL,  
    	DNFieldExtractor.DATEOFBIRTH , DNFieldExtractor.PLACEOFBIRTH , DNFieldExtractor.GENDER , DNFieldExtractor.COUNTRYOFCITIZENSHIP ,
    	DNFieldExtractor.COUNTRYOFRESIDENCE 
    };

    private UserDataVO userDataVO = null;
    private Set isModifyableSet = null;
	
    /**
	 * Constuctor that should be used from the User Data Source Implementations
	 * @param userDataVO
	 */
	public UserDataSourceVO(UserDataVO userDataVO) {
		super();
		this.userDataVO = userDataVO;
	}
	
	/**
	 * Method that should be used bu BaseUserDataSource only.
	 * @param isModifyableSet
	 */
	void setIsModifyableSet(Set isModifyableSet){
		this.isModifyableSet = isModifyableSet;
	}
	
	/**
	 * Method that returns the users userdatavo.
	 */
	public UserDataVO getUserDataVO(){
		return userDataVO;
	}
	
	/**
	 * Method used to check if a field can be modifyable by the RA.
	 * 
	 * @param field constaining one of the UserDataSourceVO.ISMODIFYABLE_ or
	 * DNFieldExtractor constants defined in the AVAILABLEMODIFYABLEFIELDS array.
	 * @return true if the field should be modifyable.
	 */
	public boolean isFieldModifyable(int field){
		return isModifyableSet.contains(new Integer(field));
	}	
	
	/**
	 * Method returning the complete isModifyable Set, it is recommended
	 * that the isFieldModifyable(int field) method is used instead.
	 * 
	 * @return the complete isFieldModifyable Set
	 */
	public Set getIsFieldModifyableSet(){
		return isModifyableSet;
	}		


}
