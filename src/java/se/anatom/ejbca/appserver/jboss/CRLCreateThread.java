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
 
package se.anatom.ejbca.appserver.jboss;

import java.util.Calendar;
import java.util.Date;

import javax.ejb.EJBException;
import javax.naming.Context;
import javax.naming.InitialContext;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.crl.ICreateCRLSessionHome;
import se.anatom.ejbca.ca.crl.ICreateCRLSessionRemote;
import se.anatom.ejbca.log.Admin;



/** 
 * A thread managing the automatic creation of CRLs.
*/
public class CRLCreateThread extends Thread 
{ 
    private static Logger log = Logger.getLogger(CRLCreateThread.class);

    /** Constants used internally. */
  private static final int CHECK_DAILY     = 1;
  private static final int CHECK_HOURLY = 2;
  private static final int CHECK_30MIN    = 3;
  private static final int CHECK_15MIN    = 4;
  private static final int CHECK_1MIN      = 5;
  	  
  private boolean run = false;
  private int check = 0; 
  private ICreateCRLSessionRemote createcrlsession = null;
  private Admin administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);;
  
   public CRLCreateThread(String polltime){
   	    super();
   	    
    	if(polltime.equalsIgnoreCase(CRLCreateService.POLLTIME_DAILY)){
     		check = CHECK_DAILY;
     	}
   	    if(polltime.equalsIgnoreCase(CRLCreateService.POLLTIME_HOURLY)){
   		  check = CHECK_HOURLY;
   	    }
   	    if(polltime.equalsIgnoreCase(CRLCreateService.POLLTIME_30MIN)){
   		  check = CHECK_30MIN;
   	    }
   	    if(polltime.equalsIgnoreCase(CRLCreateService.POLLTIME_15MIN)){
   		  check = CHECK_15MIN;
   	    }   
   	    if(polltime.equalsIgnoreCase(CRLCreateService.POLLTIME_1MIN)){
   		  check = CHECK_1MIN;
   	    }
   	    
   	    try{
                Context context = new InitialContext();
                ICreateCRLSessionHome home = (ICreateCRLSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
                          "CreateCRLSession"), ICreateCRLSessionHome.class);
                this.createcrlsession = home.create(); 
        }catch(Exception e){
   	    	throw new EJBException(e);
   	    }   	      
   	    
   }


  public void run() 
  {
       run=true;
       while(run){
       	  try{       	  	       	   
       	    sleep(getTimeToNextPoll());       	    
       	    try{      
       	      if(run)	
       	        this.createcrlsession.createCRLs(administrator);
              log.debug("CRLCreateThread: createCRLs");
       	    }catch(Exception e){
       	    	throw new EJBException(e);
       	    }       	    
       	  }catch( InterruptedException e){}
       }        
  }

  public void stopThread()
  {
  	this.run = false;
    this.check = 0;  	
  }
  
  
  /**
   * Method calculating the time i milliseconds to the next Poll  
   */
  
  private long getTimeToNextPoll(){      
      long nexttime = 0;
  	  Calendar curcalendar = Calendar.getInstance();
      Calendar nextcalendar = Calendar.getInstance();

      int modulus;
      switch(check){
           case CHECK_DAILY :
               nextcalendar.add(Calendar.DATE,1);
               nextcalendar.set(Calendar.HOUR_OF_DAY,0);
               nextcalendar.set(Calendar.MINUTE, 0);
               nextcalendar.set(Calendar.SECOND, 0);
               nexttime = nextcalendar.getTimeInMillis();               
               break;
           case CHECK_HOURLY :
               nextcalendar.add(Calendar.HOUR_OF_DAY,1);               
               nextcalendar.set(Calendar.MINUTE, 0);
               nextcalendar.set(Calendar.SECOND, 0);
               nexttime = nextcalendar.getTimeInMillis();
               break;
           case CHECK_30MIN :               
               nextcalendar.add(Calendar.MINUTE,(30 - (nextcalendar.get(Calendar.MINUTE) % 30)));               
               nextcalendar.set(Calendar.SECOND, 0);
               nexttime = nextcalendar.getTimeInMillis();
               break;
           case CHECK_15MIN :
               nextcalendar.add(Calendar.MINUTE,(15 - (nextcalendar.get(Calendar.MINUTE) % 15)));               
               nextcalendar.set(Calendar.SECOND, 0);
               nexttime = nextcalendar.getTimeInMillis(); 
               break;
           case CHECK_1MIN :
               nextcalendar.add(Calendar.MINUTE,1);               
               nextcalendar.set(Calendar.SECOND, 0);
               nexttime = nextcalendar.getTimeInMillis(); 
               break;
      }            

      
       
  	  return nexttime - (new Date()).getTime();
  }

 
    
}