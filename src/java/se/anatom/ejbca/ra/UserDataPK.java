package se.anatom.ejbca.ra;

/**
 * The primary key of the User is the username fingerprint which should be unique.
 **/
public class UserDataPK implements java.io.Serializable {
    public String username;

    public UserDataPK(String username) {
        this.username = username;
    }
    public UserDataPK() {
    }
    public int hashCode( ){
        return username.hashCode();
    }
    public boolean equals(Object obj){
            return ((UserDataPK)obj).username.equals(username);
    }
    public String toString(){
       return username.toString();
    }

}
