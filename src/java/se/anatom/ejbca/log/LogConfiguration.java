package se.anatom.ejbca.log;

import java.util.HashMap;


/**
 * Class containing the log configuration data. Tells which events
 * should be logged and if internal log database and/or external logging device
 * should be used.
 *
 * @version $Id: LogConfiguration.java,v 1.4 2003-04-01 11:27:23 scop Exp $
 */
public class LogConfiguration implements java.io.Serializable {

    // Public constants

    // Constructors
    public LogConfiguration(){
      this.useexternaldevices=true;
      this.uselogdb=true;
      this.configurationdata = new HashMap();

      // Fill log configuration data with values from LogEntry constants. Default is true for all events.
      for(int i = 0; i < LogEntry.EVENTNAMES_INFO.length; i++){
         configurationdata.put(new Integer(i), Boolean.TRUE);
      }
      for(int i = 0; i < LogEntry.EVENTNAMES_ERROR.length; i++){
         configurationdata.put(new Integer(i + LogEntry.EVENT_ERROR_BOUNDRARY), Boolean.TRUE);
      }

    }

    // Public Methods

    public boolean logEvent(int event){
      Boolean log = (Boolean) configurationdata.get(new Integer(event));
      if(log == null)
        return true; // Default is log everything.
      else
        return log.booleanValue();
    }

    public Boolean getLogEvent(int event){
      return (Boolean) configurationdata.get(new Integer(event));
    }

    public void setLogEvent(int event, boolean log){
       configurationdata.put(new Integer(event), Boolean.valueOf(log));
    }

    public boolean useLogDB(){
      return uselogdb;
    }

    public void setUseLogDB(boolean use){
      this.uselogdb=use;
    }

    public boolean useExternalLogDevices(){
      return this.useexternaldevices;
    }

    public void setUseExternalLogDevices(boolean use){
      this.useexternaldevices=use;
    }

    // Private functions

    public String getStringRepresentationOfEventId(int event){
       if(event >= LogEntry.EVENT_ERROR_BOUNDRARY)
         return LogEntry.EVENTNAMES_ERROR[event];
       else
         return LogEntry.EVENTNAMES_INFO[event];
    }

    // Private fields
    private    HashMap        configurationdata;
    private    boolean        uselogdb;
    private    boolean        useexternaldevices;


}
