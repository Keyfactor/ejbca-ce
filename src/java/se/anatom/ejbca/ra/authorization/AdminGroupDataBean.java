package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.RemoveException;
import javax.naming.InitialContext;
import java.util.Collection;
import java.util.Arrays;
import java.util.Vector;
import java.util.Iterator;
import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing authorization admingroup.
 * Information stored:
 * <pre>
 * Usergroupname
 *
 * AccessRules
 * Admin entities
 * </pre>
 *
 * @version $Id: AdminGroupDataBean.java,v 1.5 2003-02-28 09:26:46 koen_serry Exp $
 */
public abstract class AdminGroupDataBean extends BaseEntityBean {

    private static Logger log = Logger.getLogger(AdminGroupDataBean.class);

    public abstract String getAdminGroupName();
    public abstract void setAdminGroupName(String admingroupname);

    public abstract Collection getAdminEntities();
    public abstract void setAdminEntities(Collection adminentities);

    public abstract Collection getAccessRules();
    public abstract void setAccessRules(Collection accessrules);

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */

    public void addAccessRule(String resource, int rule, boolean recursive){
      try{
        AccessRulesDataLocal data = createAccessRule(resource,rule,recursive);

        Iterator i =  getAccessRules().iterator();
        while(i.hasNext()){
          AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
          if(ar.getResource().equals(resource)){
            getAccessRules().remove(ar);
            try{
              ar.remove();
            }catch(RemoveException e){ throw new EJBException(e.getMessage());}
            break;
         }
       }
       getAccessRules().add(data);
     }catch(Exception e){
     }
   } // addAccessRule

    public void addAccessRules(AccessRule[] accessrules){
      if(accessrules!=null){
        for(int i = 0; i< accessrules.length ; i++){
          addAccessRule(accessrules[i].getResource(),accessrules[i].getRule()
                                                    ,accessrules[i].isRecursive());
       }
     }
   } // addAccessRules

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public void removeAccessRule(String resource){
      Iterator i =  getAccessRules().iterator();
      while(i.hasNext()){
        AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
        if(ar.getResource().equals(resource)){
          getAccessRules().remove(ar);
          try{
            ar.remove();
          }catch(RemoveException e){ throw new EJBException(e.getMessage());}
          break;
       }
     }
    } // removeAccessRule

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public int getNumberOfAccessRules(){
       return  getAccessRules().size();
    } // getNumberOfAccessRules

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public AccessRule[] getAccessRulesAsArray(){
      AccessRule[] returnval = null;
      if(getAccessRules() != null){
        returnval = new AccessRule[getAccessRules().size()];
        Iterator i =  getAccessRules().iterator();
        int j=0;
        while(i.hasNext()){
          AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
          returnval[j] = ar.getAccessRule();
          j++;
        }
        Arrays.sort(returnval);
      }
      return returnval;
    } // getAccessRules

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */

    public void addAdminEntity(int matchwith, int matchtype, String matchvalue){
      try{
        AdminEntityDataLocal data = createAdminEntity(matchwith,matchtype,matchvalue);
        AdminEntityPK datapk = new AdminEntityPK(getAdminGroupName(), matchwith,matchtype,matchvalue);

        Iterator i =  getAdminEntities().iterator();
        while(i.hasNext()){
          AdminEntityDataLocal ue = (AdminEntityDataLocal) i.next();
          AdminEntityPK uepk= new AdminEntityPK(getAdminGroupName(), ue.getMatchWith().intValue()
                                              ,ue.getMatchType().intValue(),ue.getMatchValue());
          if(uepk.equals(datapk)){
            getAdminEntities().remove(ue);
            try{
              ue.remove();
            }catch(RemoveException e){ throw new EJBException(e.getMessage());}
            break;
         }
       }
       getAdminEntities().add(data);
     }catch(Exception e){}
    } // addAdminEntity

    public void addAdminEntities(AdminEntity[] adminentities){
      if(adminentities!=null){
        for(int i = 0; i< adminentities.length ; i++){
          addAdminEntity(adminentities[i].getMatchWith(),adminentities[i].getMatchType()
                                                    ,adminentities[i].getMatchValue());
        }
      }
    } // addAdminEntities

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public void removeAdminEntity(int matchwith, int matchtype, String matchvalue){
      AdminEntityPK datapk = new AdminEntityPK(getAdminGroupName(), matchwith,matchtype,matchvalue);

      Iterator i =  getAdminEntities().iterator();
      while(i.hasNext()){
        AdminEntityDataLocal ue = (AdminEntityDataLocal) i.next();
        AdminEntityPK uepk= new AdminEntityPK(getAdminGroupName(), ue.getMatchWith().intValue(),ue.getMatchType().intValue(),ue.getMatchValue());
        if(uepk.equals(datapk)){
          getAdminEntities().remove(ue);
          try{
            ue.remove();
          }catch(RemoveException e){ throw new EJBException(e.getMessage());}
          break;
       }
     }
    } // removeAdminEntity

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public int getNumberOfAdminEntities(){
      return getAdminEntities().size();
    } // getNumberOfAdminEntities

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public AdminEntity[] getAdminEntitiesAsArray(){
      AdminEntity[] returnval = null;
      if(getAdminEntities() != null){
        returnval = new AdminEntity[getAdminEntities().size()];
        Iterator i =  getAdminEntities().iterator();
        int j=0;
        while(i.hasNext()){
          AdminEntityDataLocal ue = (AdminEntityDataLocal) i.next();
          returnval[j] = ue.getAdminEntity();
          j++;
        }
        Arrays.sort(returnval);
      }
      return returnval;
    } // getAdminEntities

     /**
     * @see se.anatom.ejbca.ra.authorization.AdminGroupDataLocal
     */
    public AdminGroup getAdminGroup(){
      Vector accessrules = new Vector();
      Vector adminentities = new Vector();

      Iterator i = null;
      if(getAdminEntities()!=null){
        i =  getAdminEntities().iterator();
        while(i.hasNext()){
          AdminEntityDataLocal ue = (AdminEntityDataLocal) i.next();
          adminentities.addElement(ue.getAdminEntity());
        }
      }

      if(getAccessRules()!=null){
        i =  getAccessRules().iterator();
        while(i.hasNext()){
          AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
          accessrules.addElement(ar.getAccessRule());
        }
      }

      return new AdminGroup(accessrules, adminentities);
    } // getAdminGroup


    //

    // Fields required by Container

    //

    /**

     * Entity Bean holding data of raadmin profilegroups.

     * @param admingroupname.

     *

     **/

    public String ejbCreate(String admingroupname) throws CreateException {

        setAdminGroupName(admingroupname);

        log.debug("Created admingroup : "+admingroupname);

        return null;
    }

    public void ejbPostCreate(String admingroupname) {

        // Do nothing. Required.

    }

    // Private Methods.
    private AdminEntityDataLocal createAdminEntity(int matchwith, int matchtype, String matchvalue) throws CreateException, javax.naming.NamingException{
      AdminEntityDataLocal returnval = null;
      InitialContext initial = new InitialContext();
      AdminEntityDataLocalHome home = (AdminEntityDataLocalHome) initial.lookup("java:comp/env/ejb/AdminEntityDataLocal");
      returnval= home.create(getAdminGroupName(), matchwith, matchtype, matchvalue);
      return returnval;
    } // createProfileData

    private AccessRulesDataLocal createAccessRule(String resource, int rule, boolean recursive) throws CreateException, javax.naming.NamingException{
      AccessRulesDataLocal returnval = null;
      InitialContext initial = new InitialContext();
      AccessRulesDataLocalHome home = (AccessRulesDataLocalHome) initial.lookup("java:comp/env/ejb/AccessRulesDataLocal");
      returnval= home.create(getAdminGroupName(), resource, new AccessRule(resource,rule,recursive));
      return returnval;
    } // createProfileData
}
