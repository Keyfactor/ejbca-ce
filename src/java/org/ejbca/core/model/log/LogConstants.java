package org.ejbca.core.model.log;

/**
 * @version $Id: LogConstants.java,v 1.1 2006-01-17 20:28:08 anatom Exp $
 */
public interface LogConstants {

    public static final int MAXIMUM_QUERY_ROWCOUNT = 300;

    /**
     * Constant containing caid that couldn't be determined in any other way. Log events can only be viewed.
     * by superadministrator.
     */
    public static final int INTERNALCAID = 0;
}
