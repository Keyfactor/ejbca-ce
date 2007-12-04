package org.ejbca.core.model.log;

/**
 * Class that is invoked when something has gone wrong.
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
