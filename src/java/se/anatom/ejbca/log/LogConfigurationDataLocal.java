package se.anatom.ejbca.log;

/**
 * For docs, see LogConfigurationDataBean
 **/
public interface LogConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods

    public Integer getId();
    
    public LogConfiguration loadLogConfiguration();
    
    public void saveLogConfiguration(LogConfiguration logconfiguration);
    
    public Integer getAndIncrementRowCount();
}

