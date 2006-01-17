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
 
package org.ejbca.appserver.jboss;

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