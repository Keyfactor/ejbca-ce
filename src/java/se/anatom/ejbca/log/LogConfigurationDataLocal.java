package se.anatom.ejbca.log;

/**
 * For docs, see LogConfigurationDataBean
 */
public interface LogConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public LogConfiguration loadLogConfiguration();

    /**
     * DOCUMENT ME!
     *
     * @param logconfiguration DOCUMENT ME!
     */
    public void saveLogConfiguration(LogConfiguration logconfiguration);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Integer getAndIncrementRowCount();
}
