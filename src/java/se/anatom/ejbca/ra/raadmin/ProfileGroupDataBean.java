package se.anatom.ejbca.ra.raadmin;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.RemoveException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Vector;
import java.util.TreeMap;
import java.util.Iterator;
import org.apache.log4j.*;

import se.anatom.ejbca.webdist.rainterface.Profile;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing ra admin  user preference.
 * Information stored:
 * <pre>
 * Id  (BigInteger SerialNumber)
 * UserPreference
 * </pre>
 *
 **/

public abstract class ProfileGroupDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(UserPreferencesDataBean.class.getName() );


    protected EntityContext  ctx;

    public abstract String getProfileGroupName();

    public abstract void setProfileGroupName(String name);
    
    public abstract Collection getProfilesData();
    
    public abstract void setProfilesData(Collection profilesdata);
            
    public abstract Collection ejbSelectProfiles(String profilegroupname) throws javax.ejb.FinderException; 
    
    public abstract Collection ejbSelectProfile(String profilegroupname, String profilename) throws javax.ejb.FinderException; 

     /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */     
    public boolean addProfile(String profilename, Profile profile)  {
        boolean returnvalue = true;
        try{
          ProfileDataLocal profiledata = createProfileData(profilename, profile);
          Iterator i =  getProfilesData().iterator();

          while(i.hasNext()){
            ProfileDataLocal pdl =  (ProfileDataLocal) i.next();
            if(pdl.getProfileName().equals(profilename)){
              returnvalue = false;   
            }
          }
          if(returnvalue) // Profilename doesn't already exist, add profile.
            getProfilesData().add(profiledata);          
        }catch(Exception e){
          returnvalue =false;   
        }
        return returnvalue;
    } // addProfile 
 
    /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */         
    public boolean cloneProfile(String originalprofilename, String newprofilename){
       boolean returnvalue = false;
       Profile profile = null;
       Iterator i = getProfilesData().iterator();
       while(i.hasNext()){
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();
            if(pdl.getProfileName().equals(originalprofilename)){
              returnvalue = true; 
              profile = pdl.getProfile();
            }    
       }
       if(returnvalue){
          try{ 
            ProfileDataLocal profiledata = createProfileData(newprofilename, profile);
            getProfilesData().add(profiledata);
          }catch(Exception e){
            returnvalue=false;   
           //throw new EJBException(e.getMessage());  
          }
       }
       return returnvalue;
       
    } // cloneProfile
        
    /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */         
    public void removeProfile(String profilename)  {
       Iterator i = getProfilesData().iterator();     
        while(i.hasNext()){
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();
            if(pdl.getProfileName().equals(profilename)){
                getProfilesData().remove(pdl);     
                try{
                  pdl.remove();
                }catch(RemoveException e){ throw new EJBException(e.getMessage());}
                break;              
           }    
       }     
    } // removeProfile

    /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */         
    public boolean renameProfile(String oldprofilename, String newprofilename){
       boolean returnvalue = false;
       Profile profile = null;
       Iterator i = getProfilesData().iterator();           
        while(i.hasNext()){           
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();        
            if(pdl.getProfileName().equals(oldprofilename)){
              profile = pdl.getProfile();  
              try{
                getProfilesData().remove(pdl);
                pdl.remove();
                ProfileDataLocal profiledata = createProfileData(newprofilename, profile);
                getProfilesData().add(profiledata);
                returnvalue=true;
                break;
              }catch(Exception e){
                 returnvalue=false;   
              }
            }    
       }        
       return returnvalue;
    } // remameProfile

     /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */     
    public boolean changeProfile(String profilename, Profile profile){
       boolean returnvalue = false;
       Iterator i = getProfilesData().iterator();        
        while(i.hasNext()){
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();
            if(pdl.getProfileName().equals(profilename)){
                pdl.setProfile(profile);  
                returnvalue=true;
            }    
       }        
       return returnvalue;        
    } // changeProfile
    
    /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */       
    public Collection getProfileNames(){
      Vector returnval = null;
      Collection result = null;
      try{
        result = ejbSelectProfiles(getProfileGroupName());
        if(result.size()>0){
          returnval = new Vector();  
          Iterator i = result.iterator();
          while(i.hasNext()){
            returnval.add(((ProfileDataLocal) i.next()).getProfileName());
          }
        }
      }catch(Exception e){
        returnval=null;   
      }
      return returnval;         
    } // getProfileName

    /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */     
    public TreeMap getProfiles(){
      TreeMap returnval = null;
      Collection result = null;
      try{
        result = ejbSelectProfiles(getProfileGroupName());
        if(result.size()>0){
          returnval = new TreeMap();  
          Iterator i = result.iterator();
          while(i.hasNext()){
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();
            returnval.put(pdl.getProfileName(),pdl.getProfile());
          }
        }
      }catch(Exception e){
        returnval=null;             
                //    throw new EJBException(e.getMessage());    

      }
      return returnval;        
    } // getProfiles
    
     /**

     * @see se.anatom.ejbca.ra.raadmin.ProfileGroupDataLocal

     */     
    public Profile getProfile(String profilename){
      Profile returnval = null;
      Collection result;
      try{
        result = ejbSelectProfile(getProfileGroupName(), profilename);
        Iterator i = result.iterator();
        if(i.hasNext()){
          returnval = ((ProfileDataLocal) i.next()).getProfile();   
        }
      }catch(Exception e){
        returnval=null;            
                  //  throw new EJBException(e.getMessage());    
 
      }
      return returnval;             
    } // getProfile
    
    
    //

    // Fields required by Container

    //

    /**

     * Entity Bean holding data of raadmin profilegroups.

     * @param profilegroupname.

     *

     **/

    public String ejbCreate(String profilegroupname) throws CreateException {
        
        setProfileGroupName(profilegroupname);

        log.debug("Created profilegroup : "+profilegroupname);

        return null;
    }

    public void ejbPostCreate(String profilegroupname) {

        // Do nothing. Required.

    }

    public void setEntityContext(EntityContext ctx) {

        this.ctx = ctx;

    }

    public void unsetEntityContext() {

        this.ctx = null;

    }

    public void ejbActivate() {

        // Not implemented.

    }

    public void ejbPassivate() {

        // Not implemented.

    }

    public void ejbLoad() {

        // Not implemented.

    }

    public void ejbStore() {

        // Not implemented.

    }

    public void ejbRemove() {

        // Not implemented.

    }
    
    // Private Methods.
    private ProfileDataLocal createProfileData(String profilename, Profile profile) throws CreateException, javax.naming.NamingException{
      ProfileDataLocal returnval = null;  
      InitialContext initial = new InitialContext();
      ProfileDataLocalHome home = (ProfileDataLocalHome) initial.lookup("java:comp/env/ejb/ProfileDataLocal");
      returnval= home.create(profilename, profile);
      return returnval; 
    } // createProfileData
    

}