package org.ejbca.core.model.log;

/**
 * @version $Id: LogConstants.java,v 1.2 2006-12-20 08:33:32 anatom Exp $
 */
public interface LogConstants {

	/** Constant limiting thenumber of rows returned when querying logfiles to be viewed by in the admin-GUI
	 */
    public static final int MAXIMUM_QUERY_ROWCOUNT = 1000;

    /**
     * Constant containing caid that couldn't be determined in any other way. Log events can only be viewed.
     * by superadministrator.
     */
    public static final int INTERNALCAID = 0;
}
