package se.anatom.ejbca.ra.authorization;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.RemoveException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Arrays;
import java.util.Vector;
import java.util.Iterator;
import org.apache.log4j.*;


/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing authorization usergroup.
 * Information stored:
 * <pre>
 * Usergroupname
 *
 * AccessRules
 * Userentities
 * </pre>
 *
 * @version $Id: UserGroupDataBean.java,v 1.2 2002-07-23 16:02:58 anatom Exp $
 **/

public abstract class UserGroupDataBean implements javax.ejb.EntityBean {

    private static Category log = Category.getInstance(UserGroupDataBean.class.getName() );

    protected EntityContext  ctx;

    public abstract String getUserGroupName();
    public abstract void setUserGroupName(String usergroupname);

    public abstract Collection getUserEntities();
    public abstract void setUserEntities(Collection userentities);

    public abstract Collection getAccessRules();
    public abstract void setAccessRules(Collection accessrules);

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */

    public void addAccessRule(String directory, int rule, boolean recursive){
      try{
        AccessRulesDataLocal data = createAccessRule(directory,rule,recursive);

        Iterator i =  getAccessRules().iterator();
        while(i.hasNext()){
          AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
          if(ar.getDirectory().equals(directory)){
            getAccessRules().remove(ar);
            try{
              ar.remove();
            }catch(RemoveException e){ throw new EJBException(e.getMessage());}
            break;
         }
       }
       getAccessRules().add(data);
     }catch(Exception e){}
   } // addAccessRule

    public void addAccessRules(AccessRule[] accessrules){
      if(accessrules!=null){
        for(int i = 0; i< accessrules.length ; i++){
          addAccessRule(accessrules[i].getDirectory(),accessrules[i].getRule()
                                                    ,accessrules[i].isRecursive());
       }
     }
   } // addAccessRules

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public void removeAccessRule(String directory){
      Iterator i =  getAccessRules().iterator();
      while(i.hasNext()){
        AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
        if(ar.getDirectory().equals(directory)){
          getAccessRules().remove(ar);
          try{
            ar.remove();
          }catch(RemoveException e){ throw new EJBException(e.getMessage());}
          break;
       }
     }
    } // removeAccessRule

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public int getNumberOfAccessRules(){
       return  getAccessRules().size();
    } // getNumberOfAccessRules

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
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
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */

    public void addUserEntity(int matchwith, int matchtype, String matchvalue){
      try{
        UserEntityDataLocal data = createUserEntity(matchwith,matchtype,matchvalue);
        UserEntityPK datapk = new UserEntityPK(getUserGroupName(), matchwith,matchtype,matchvalue);

        Iterator i =  getUserEntities().iterator();
        while(i.hasNext()){
          UserEntityDataLocal ue = (UserEntityDataLocal) i.next();
          UserEntityPK uepk= new UserEntityPK(getUserGroupName(), ue.getMatchWith().intValue()
                                              ,ue.getMatchType().intValue(),ue.getMatchValue());
          if(uepk.equals(datapk)){
            getUserEntities().remove(ue);
            try{
              ue.remove();
            }catch(RemoveException e){ throw new EJBException(e.getMessage());}
            break;
         }
       }
       getUserEntities().add(data);
     }catch(Exception e){}
    } // addUserEntity

    public void addUserEntities(UserEntity[] userentities){
      if(userentities!=null){
        for(int i = 0; i< userentities.length ; i++){
          addUserEntity(userentities[i].getMatchWith(),userentities[i].getMatchType()
                                                    ,userentities[i].getMatchValue());
        }
      }
    } // addUserEntities

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public void removeUserEntity(int matchwith, int matchtype, String matchvalue){
      UserEntityPK datapk = new UserEntityPK(getUserGroupName(), matchwith,matchtype,matchvalue);

      Iterator i =  getUserEntities().iterator();
      while(i.hasNext()){
        UserEntityDataLocal ue = (UserEntityDataLocal) i.next();
        UserEntityPK uepk= new UserEntityPK(getUserGroupName(), ue.getMatchWith().intValue(),ue.getMatchType().intValue(),ue.getMatchValue());
        if(uepk.equals(datapk)){
          getUserEntities().remove(ue);
          try{
            ue.remove();
          }catch(RemoveException e){ throw new EJBException(e.getMessage());}
          break;
       }
     }
    } // removeUserEntity

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public int getNumberOfUserEntities(){
      return getUserEntities().size();
    } // getNumberOfUserEntities

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public UserEntity[] getUserEntitiesAsArray(){
      UserEntity[] returnval = null;
      if(getUserEntities() != null){
        returnval = new UserEntity[getUserEntities().size()];
        Iterator i =  getUserEntities().iterator();
        int j=0;
        while(i.hasNext()){
          UserEntityDataLocal ue = (UserEntityDataLocal) i.next();
          returnval[j] = ue.getUserEntity();
          j++;
        }
        Arrays.sort(returnval);
      }
      return returnval;
    } // getUserEntities

     /**
     * @see se.anatom.ejbca.ra.raadmin.UserGroupDataLocal
     */
    public UserGroup getUserGroup(){
      Vector accessrules = new Vector();
      Vector userentities = new Vector();

      Iterator i = null;
      if(getUserEntities()!=null){
        i =  getUserEntities().iterator();
        while(i.hasNext()){
          UserEntityDataLocal ue = (UserEntityDataLocal) i.next();
          userentities.addElement(ue.getUserEntity());
        }
      }

      if(getAccessRules()!=null){
        i =  getAccessRules().iterator();
        while(i.hasNext()){
          AccessRulesDataLocal ar = (AccessRulesDataLocal) i.next();
          accessrules.addElement(ar.getAccessRule());
        }
      }

      return new UserGroup(accessrules, userentities);
    } // getUserGroup


    //

    // Fields required by Container

    //

    /**

     * Entity Bean holding data of raadmin profilegroups.

     * @param usergroupname.

     *

     **/

    public String ejbCreate(String usergroupname) throws CreateException {

        setUserGroupName(usergroupname);

        log.debug("Created usergroup : "+usergroupname);

        return null;
    }

    public void ejbPostCreate(String usergroupname) {

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

    }

    // Private Methods.
    private UserEntityDataLocal createUserEntity(int matchwith, int matchtype, String matchvalue) throws CreateException, javax.naming.NamingException{
      UserEntityDataLocal returnval = null;
      InitialContext initial = new InitialContext();
      UserEntityDataLocalHome home = (UserEntityDataLocalHome) initial.lookup("java:comp/env/ejb/UserEntityDataLocal");
      returnval= home.create(getUserGroupName(), matchwith, matchtype, matchvalue);
      return returnval;
    } // createProfileData

    private AccessRulesDataLocal createAccessRule(String directory, int rule, boolean recursive) throws CreateException, javax.naming.NamingException{
      AccessRulesDataLocal returnval = null;
      InitialContext initial = new InitialContext();
      AccessRulesDataLocalHome home = (AccessRulesDataLocalHome) initial.lookup("java:comp/env/ejb/AccessRulesDataLocal");
      returnval= home.create(getUserGroupName(), directory, new AccessRule(directory,rule,recursive));
      return returnval;
    } // createProfileData
}