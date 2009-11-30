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
package org.ejbca.core.model.log;

/**
 * Class that is invoked when something has gone wrong.
 * @version $Id$
 */
public interface IProtectedLogAction {

	// Error codes
	public static final String CAUSE_UNKNOWN						= "protectedlog.cause.unknown";
	public static final String CAUSE_INTERNAL_ERROR			= "protectedlog.cause.internalerror";
	public static final String CAUSE_TESTING							= "protectedlog.cause.testing";
	public static final String CAUSE_MISSING_TOKEN				= "protectedlog.cause.missingtoken";
	public static final String CAUSE_MODIFIED_TOKEN			= "protectedlog.cause.modifiedtoken";
	public static final String CAUSE_MISSING_LOGROW			= "protectedlog.cause.missinglogrow";
	public static final String CAUSE_MODIFIED_LOGROW		= "protectedlog.cause.modifiedlogrow";
	public static final String CAUSE_EMPTY_LOG					= "protectedlog.cause.emptylog";
	public static final String CAUSE_ROLLED_BACK				= "protectedlog.cause.rolledback";
	public static final String CAUSE_FROZEN							= "protectedlog.cause.frozen";
	public static final String CAUSE_INVALID_TOKEN				= "protectedlog.cause.invalidtoken";
	public static final String CAUSE_MODIFIED_EXPORT			= "protectedlog.cause.modifiedexport";
	public static final String CAUSE_INVALID_EXPORT			= "protectedlog.cause.invalidexport";
	public static final String CAUSE_UNVERIFYABLE_CHAIN	= "protectedlog.cause.unverifyablechain";

	/**
	 * Invoked when something has gone wrong.
	 * @param causeIdentifier is one of the IProtectedLogAction.CAUSE_* error codes.
	 */
	public abstract void action(String causeIdentifier);

}
