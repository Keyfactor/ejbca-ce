package se.anatom.ejbca.admin;

import java.util.Random;
import java.util.*;
import java.lang.Integer;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
 

public class ra {


    public static void main(String [] args){
        /*
        try {
            IAdminCommand cmd = RaAdminCommandFactory.getCommand(args);
            if (cmd != null) {
                cmd.execute();
            } else {
            System.out.println("Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser");
            }            
        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
        */
        if (args.length < 1) {
            System.out.println("Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser");
            return;
        }
        try {
            org.apache.log4j.PropertyConfigurator.configure();
            Context jndiContext = getInitialContext();

            Object obj1 = jndiContext.lookup("UserAdminSession");
            IUserAdminSessionHome adminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
            IUserAdminSession admin = adminhome.create();
            if (args[0].equals("adduser"))
            {
                if (args.length < 6) {
                    System.out.println("Usage: RA adduser <username> <password> <dn> <email> <type>");
                    System.out.println("Type (mask): INVALID=0; END-USER=1; CA=2; RA=4; ROOTCA=8; CAADMIN=16; RAADMIN=0x32");
                    return;
                }
                String username = args[1];
                String password = args[2];
                String dn = args[3];
                String email = args[4];
                int type = Integer.parseInt(args[5]);

                System.out.println("Trying to add user:");
                System.out.println("Username: "+username);
                System.out.println("Password (hashed only): "+password);
                System.out.println("DN: "+dn);
                System.out.println("Email: "+email);
                System.out.println("Type: "+type);
                if (email.equals("null"))
                    email = null;
                admin.addUser(username, password, dn, email, type);
                System.out.println("User '"+username+"' has been added.");
                System.out.println();
                System.out.println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");
            } else if (args[0].equals("deluser"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA deluser <username>");
                    return;
                }
                String username = args[1];
                System.out.print("Have you revoked the user [y/N]? ");
                int inp = System.in.read();
                if ( (inp == 121) || (inp==89) ) {
                    admin.deleteUser(username);
                    System.out.println("Deleted user "+username);
                } else {
                    System.out.println("Delete aborted!");
                    System.out.println("Please run 'ra revokeuser "+username+"'.");
                }
            } else if (args[0].equals("setpwd"))
            {
                if (args.length < 3) {
                    System.out.println("Usage: RA setpwd <username> <password>");
                    return;
                }
                String username = args[1];
                String password = args[2];
                System.out.println("Setting password "+password+" for user "+username);
                admin.setPassword(username, password);
            } else if (args[0].equals("setclearpwd"))
            {
                if (args.length < 3) {
                    System.out.println("Usage: RA setclearpwd <username> <password>");
                    return;
                }
                String username = args[1];
                String password = args[2];
                System.out.println("Setting clear text password "+password+" for user "+username);
                admin.setClearTextPassword(username, password);
            } else if (args[0].equals("setuserstatus"))
            {
                if (args.length < 3) {
                    System.out.println("Usage: RA setuserstatus <username> <status>");
                    System.out.println("Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                    return;
                }
                String username = args[1];
                int status = Integer.parseInt(args[2]);
                System.out.println("New status for user "+username+" is "+status);
                admin.setUserStatus(username, status);
            } else if (args[0].equals("finduser"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA finduser <username>");
                    return;
                }
                String username = args[1];
                UserAdminData data = admin.findUser(username);
                if (data != null) {
                    System.out.println("Found user:");
                    System.out.println("username="+data.getUsername());
                    System.out.println("dn=\""+data.getDN()+"\"");
                    System.out.println("email="+data.getEmail());
                    System.out.println("status="+data.getStatus());
                    System.out.println("type="+data.getType());
                    System.out.println("password="+data.getPassword());
                } else {
                    System.out.println("User '"+username+"' does not exist.");
                }
            } else if (args[0].equals("listnewusers"))
            {
                Collection coll = admin.findAllUsersByStatus(UserData.STATUS_NEW);
                Iterator iter = coll.iterator();
                while (iter.hasNext())
                {
                    UserAdminData data = (UserAdminData)iter.next();
                    System.out.println("New user: "+data.getUsername()+", \""+data.getDN()+"\", "+data.getEmail()+", "+data.getStatus()+", "+data.getType());
                }
            } else if (args[0].equals("listusers"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA listusers <status>");
                    System.out.println("Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50");
                    return;
                }
                int status = Integer.parseInt(args[1]);
                Collection coll = admin.findAllUsersByStatus(status);
                Iterator iter = coll.iterator();
                while (iter.hasNext())
                {
                    UserAdminData data = (UserAdminData)iter.next();
                    System.out.println("New user: "+data.getUsername()+", \""+data.getDN()+"\", "+data.getEmail()+", "+data.getStatus()+", "+data.getType());
                }
            } else if (args[0].equals("revokeuser"))
            {
                if (args.length < 2) {
                    System.out.println("Usage: RA revokeuser <username>");
                    return;
                }
                String username = args[1];
                UserAdminData data = admin.findUser(username);
                System.out.println("Found user:");
                System.out.println("username="+data.getUsername());
                System.out.println("dn=\""+data.getDN()+"\"");
                System.out.println("Old status="+data.getStatus());
                admin.setUserStatus(username, UserData.STATUS_REVOKED);
                System.out.println("New status="+UserData.STATUS_REVOKED);

                Object obj2 = jndiContext.lookup("CertificateStoreSession");
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj2, ICertificateStoreSessionHome.class);
                ICertificateStoreSessionRemote store = storehome.create();
                Certificate[] certs = store.findCertificatesBySubject(data.getDN());
                // Revoke all certs
                if (certs.length > 0 ) {
                    Object obj = jndiContext.lookup("CertificateData");
                    CertificateDataHome home = (CertificateDataHome) javax.rmi.PortableRemoteObject.narrow(obj, CertificateDataHome.class);
                    for (int i=0; i<certs.length;i++) {
                        CertificateDataPK revpk = new CertificateDataPK();
                        revpk.fp = CertTools.getFingerprintAsString((X509Certificate)certs[i]);
                        CertificateData rev = home.findByPrimaryKey(revpk);
                        if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                            rev.setStatus(CertificateData.CERT_REVOKED);
                            rev.setRevocationDate(new Date());
                            System.out.println("Revoked cert with serialNumber "+Hex.encode(((X509Certificate)certs[i]).getSerialNumber().toByteArray()));
                        }
                    }
                }
            } else {
                System.out.println("Usage: RA adduser | deluser | setpwd | setclearpwd | setuserstatus | finduser | listnewusers | listusers | revokeuser");
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }

  static public Context getInitialContext() throws NamingException{
    //System.out.println(">GetInitialContext");
    Context ctx = new javax.naming.InitialContext();
    //System.out.println("<GetInitialContext");
    return ctx;
  }

}
