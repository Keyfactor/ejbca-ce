package se.anatom.ejbca.admin;

import java.util.Random;
import java.util.*;
import java.lang.Integer;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

public class ra {


    public static void main(String [] args){
        if (args.length < 1) {
            System.out.println("Usage: RA adduser|deluser|setclearpwd|setuserstatus|finduser|listnewusers");
            System.exit(1);
        }
        try {
            org.apache.log4j.BasicConfigurator.configure();
            Context jndiContext = getInitialContext();

            Object obj1 = jndiContext.lookup("UserAdminSession");
            IUserAdminSessionHome adminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
            IUserAdminSession admin = adminhome.create();
            if (args[0].equals("adduser"))
            {
                if (args.length < 6) {
                    System.out.println("Usage: RA adduser username password dn email type");
                    System.out.println("Type (mask): INVALID=0; END-USER=1; CA=2; RA=4; ROOTCA=8; CAADMIN=16; RAADMIN=0x32");
                    System.exit(1);
                }
                String username = args[1];
                String password = args[2];
                String dn = args[3];
                String email = args[4];
                int type = Integer.parseInt(args[5]);

                System.out.println("Adding user:");
                System.out.println("Username: "+username);
                System.out.println("Password (hashed only): "+password);
                System.out.println("DN: "+dn);
                System.out.println("Email: "+email);
                System.out.println("Type: "+type);
                admin.addUser(username, password, dn, email, type);
            } else if (args[0].equals("deluser"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA deluser username");
                    System.exit(1);
                }
                String username = args[1];
                System.out.println("Deleting user "+username);
                admin.deleteUser(username);
            } else if (args[0].equals("setclearpwd"))
            {
                if (args.length < 3) {
                    System.out.println("Usage: RA setclearpwd username password");
                    System.exit(1);
                }
                String username = args[1];
                String password = args[2];
                System.out.println("Setting clear text password "+password+" for user "+username);
                admin.setClearTextPassword(username, password);
            } else if (args[0].equals("setuserstatus"))
            {
                if (args.length < 3) {
                    System.out.println("Usage: RA setuserstatus username status");
                    System.out.println("Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                    System.exit(1);
                }
                String username = args[1];
                int status = Integer.parseInt(args[2]);
                System.out.println("New status for user "+username+" is "+status);
                admin.setUserStatus(username, status);
            } else if (args[0].equals("finduser"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA finduser username");
                    System.exit(1);
                }
                String username = args[1];
                UserAdminData data = admin.findUser(username);
                System.out.println("Found user:");
                System.out.println("username="+data.getUsername());
                System.out.println("dn=\""+data.getDN()+"\"");
                System.out.println("email="+data.getEmail());
                System.out.println("status="+data.getStatus());
                System.out.println("type="+data.getType());
                System.out.println("password="+data.getPassword());
            } else if (args[0].equals("listnewusers"))
            {

                Collection coll = admin.findAllUsersByStatus(UserData.STATUS_NEW);
                Iterator iter = coll.iterator();
                while (iter.hasNext())
                {
                    UserAdminData data = (UserAdminData)iter.next();
                    System.out.println("New user: "+data.getUsername()+", \""+data.getDN()+"\", "+data.getEmail()+", "+data.getStatus()+", "+data.getType());
                }
            } else {
                System.out.println("Usage: RA adduser|deluser|setclearpwd|setuserstatus|finduser|listnewusers");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

  static public Context getInitialContext() throws NamingException{
    System.out.println(">GetInitialContext");
    Context ctx = new javax.naming.InitialContext();
    System.out.println("<GetInitialContext");
    return ctx;
  }

}
