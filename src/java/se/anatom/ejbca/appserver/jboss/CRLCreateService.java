package se.anatom.ejbca.appserver.jboss;

import org.jboss.system.ServiceMBeanSupport;

/** 
 * An MBean service managing the automatic creation of CRLs.
*/
public class CRLCreateService extends ServiceMBeanSupport implements CRLCreateServiceMBean
{ 
  public static final String POLLTIME_DAILY      = "DAILY";	
  public static final String POLLTIME_HOURLY  = "HOURLY";
  public static final String POLLTIME_30MIN     = "30MIN";
  public static final String POLLTIME_15MIN     = "15MIN";
  public static final String POLLTIME_1MIN       = "1MIN";

  /** Constants used internally. */
  private static final int CHECK_DAILY     = 1;
  private static final int CHECK_HOURLY = 2;
  private static final int CHECK_30MIN    = 3;
  private static final int CHECK_15MIN    = 4;
  private static final int CHECK_1MIN      = 5;
  
	
  private String polltime; 
  private CRLCreateThread crlcreatethread;
  
  public String getPolltime()
  {
     return polltime;
  }

  public void setPolltime(String polltime)
  {
  	  this.polltime = polltime;
  }

  public String getName()
  {
    return "CRLCreateService";      
  }

  public void startService() throws Exception
  {
     this.crlcreatethread = new CRLCreateThread(getPolltime());
  	 this.crlcreatethread.start();	 
  }
  public void stopService()
  {
  	 this.crlcreatethread.stopThread();   	
  }
  
   
}