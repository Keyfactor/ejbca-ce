package se.anatom.ejbca.appserver.jboss;

/** A Jboss service that authomatically creates CRLs when neccesary.
*/
public interface CRLCreateServiceMBean extends org.jboss.system.ServiceMBean
{    
  public String getPolltime();  
  public void setPolltime(String Polltime);
    
  
}
