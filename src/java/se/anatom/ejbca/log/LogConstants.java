package se.anatom.ejbca.log;

/**
 */
public interface LogConstants {
    
    public static final int MAXIMUM_QUERY_ROWCOUNT = 300;

    /**
     * Constant containing caid that couldn't be determined in any other way. Log events can only be viewed.
     * by superadministrator.
     */
    public static final int INTERNALCAID = 0;
}
