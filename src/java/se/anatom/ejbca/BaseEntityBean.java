package se.anatom.ejbca;

import javax.ejb.EntityBean;
import javax.ejb.EntityContext;

public class BaseEntityBean implements EntityBean
{
    transient protected EntityContext  ctx;

	public BaseEntityBean()
	{
		super();
	}

    public void setEntityContext(EntityContext ctx){
         this.ctx=ctx;
    }
    public void unsetEntityContext(){
         this.ctx=null;
    }
    public void ejbActivate(){
        // Not implemented.
    }
    public void ejbPassivate(){
        // Not implemented.
    }
    public void ejbLoad(){
        // Not implemented.
    }
    public void ejbStore(){
        // Not implemented.
    }
    public void ejbRemove(){
        // Not implemented.
    }
}
