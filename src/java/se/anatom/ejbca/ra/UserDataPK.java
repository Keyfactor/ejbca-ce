package se.anatom.ejbca.ra;

/**
 * The primary key of the User is the username fingerprint which should be unique.
 **/
public class UserDataPK implements java.io.Serializable {
    public String username;

    public int hashCode( ){
        return username.hashCode();
    }
    public boolean equals(Object obj){
        if(obj instanceof UserDataPK){
            return (username == ((UserDataPK)obj).username);
        }
        return false;
    }
    public String toString(){
       return username;
    }

}
