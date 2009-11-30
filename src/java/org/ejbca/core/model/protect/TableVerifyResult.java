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

package org.ejbca.core.model.protect;

import java.io.Serializable;

/**
 * 
 * @author tomas
 * @version $Id$
 */
public class TableVerifyResult implements Serializable {

    private static final long serialVersionUID = -1L;
    
	public static final int VERIFY_SUCCESS = 0;
	public static final int VERIFY_FAILED = 1;
	public static final int VERIFY_DISABLED = 2;
	public static final int VERIFY_NO_ROW = 3;
	public static final int VERIFY_NO_KEY = 4;
	public static final int VERIFY_WRONG_HASH = 5;
	public static final int VERIFY_INCOMPATIBLE_ALG = 6;
	public static final int VERIFY_UNDETERMINED = 7;
	public static final int VERIFY_UNKNOWN_ERROR = 99;

	public static final String VERIFY_SUCCESS_MSG = "VERIFY_SUCCESS";
	public static final String VERIFY_FAILED_MSG = "VERIFY_FAILED";
	public static final String VERIFY_DISABLED_MSG = "VERIFY_DISABLED";
	public static final String VERIFY_NO_ROW_MSG = "VERIFY_NO_ROW";
	public static final String VERIFY_NO_KEY_MSG = "VERIFY_NO_KEY";
	public static final String VERIFY_WRONG_HASH_MSG = "VERIFY_WRONG_HASH";
	public static final String VERIFY_INCOMPATIBLE_ALG_MSG = "VERIFY_INCOMPATIBLE_ALG";
	public static final String VERIFY_UNDETERMINED_MSG = "VERIFY_UNDETERMINED";
	public static final String VERIFY_UNKNOWN_ERROR_MSG = "VERIFY_UNKNOWN_ERROR";
	
	/** One of the codes above */
	private int resultCode = VERIFY_SUCCESS; 

	public int getResultCode() {
		return resultCode;
	}

	public void setResultCode(int resultCode) {
		this.resultCode = resultCode;
	}

	public String getResultConstant() {
		String ret = null;
		switch (resultCode) {
		case VERIFY_SUCCESS:
			ret = VERIFY_SUCCESS_MSG;
			break;
		case VERIFY_DISABLED:
			ret = VERIFY_DISABLED_MSG;
			break;
		case VERIFY_FAILED:
			ret = VERIFY_FAILED_MSG;
			break;
		case VERIFY_NO_KEY:
			ret = VERIFY_NO_KEY_MSG;
			break;
		case VERIFY_NO_ROW:
			ret = VERIFY_NO_ROW_MSG;
			break;
		case VERIFY_WRONG_HASH:
			ret = VERIFY_WRONG_HASH_MSG;
			break;
		case VERIFY_INCOMPATIBLE_ALG:
			ret = VERIFY_INCOMPATIBLE_ALG_MSG;
			break;
		case VERIFY_UNDETERMINED:
			ret = VERIFY_UNDETERMINED_MSG;
			break;
		case VERIFY_UNKNOWN_ERROR:
			ret = VERIFY_UNKNOWN_ERROR_MSG;
			break;
		default:
			break;
		}
		return ret;
	}

}
