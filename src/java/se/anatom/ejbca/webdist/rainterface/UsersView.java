/*
 * UsersView.java
 *
 * Created on den 18 april 2002, 23:00
 */
package se.anatom.ejbca.webdist.rainterface;

import se.anatom.ejbca.ra.UserAdminData;

import java.rmi.RemoteException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import javax.naming.NamingException;


/**
 * A class representing a set of users w
 *
 * @author philip
 */
public class UsersView {
    /**
     * Creates a new instance of UsersView
     */
    public UsersView() {
        users = new ArrayList();
        sortby = new SortBy();
    }

    /**
     * Creates a new UsersView object.
     *
     * @param importuser DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     */
    public UsersView(UserAdminData importuser)
        throws RemoteException, NamingException, FinderException, CreateException {
        users = new ArrayList();
        sortby = new SortBy();
        users.add(new UserView(importuser));

        Collections.sort(users);
    }

    /**
     * Creates a new UsersView object.
     *
     * @param importusers DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     */
    public UsersView(Collection importusers)
        throws RemoteException, NamingException, FinderException, CreateException {
        users = new ArrayList();
        sortby = new SortBy();

        setUsers(importusers);
    }

    // Public methods.
    public void sortBy(int sortby, int sortorder) {
        this.sortby.setSortBy(sortby);
        this.sortby.setSortOrder(sortorder);

        Collections.sort(users);
    }

    /**
     * DOCUMENT ME!
     *
     * @param index DOCUMENT ME!
     * @param size DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public UserView[] getUsers(int index, int size) {
        int endindex;
        UserView[] returnval;

        if (index > users.size()) {
            index = users.size() - 1;
        }

        if (index < 0) {
            index = 0;
        }

        endindex = index + size;

        if (endindex > users.size()) {
            endindex = users.size();
        }

        returnval = new UserView[endindex - index];

        int end = endindex - index;

        for (int i = 0; i < end; i++) {
            returnval[i] = (UserView) users.get(index + i);
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param users DOCUMENT ME!
     */
    public void setUsers(UserView[] users) {
        this.users.clear();

        if ((users != null) && (users.length > 0)) {
            for (int i = 0; i < users.length; i++) {
                users[i].setSortBy(this.sortby);
                this.users.add(users[i]);
            }
        }

        Collections.sort(this.users);
    }

    /**
     * DOCUMENT ME!
     *
     * @param users DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     */
    public void setUsers(UserAdminData[] users)
        throws RemoteException, NamingException, FinderException, CreateException {
        UserView user;
        this.users.clear();

        if ((users != null) && (users.length > 0)) {
            for (int i = 0; i < users.length; i++) {
                user = new UserView(users[i]);
                user.setSortBy(this.sortby);
                this.users.add(user);
            }

            Collections.sort(this.users);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param importusers DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     * @throws NamingException DOCUMENT ME!
     * @throws FinderException DOCUMENT ME!
     * @throws CreateException DOCUMENT ME!
     */
    public void setUsers(Collection importusers)
        throws RemoteException, NamingException, FinderException, CreateException {
        UserView user;
        Iterator i;
        this.users.clear();

        if ((importusers != null) && (importusers.size() > 0)) {
            i = importusers.iterator();

            while (i.hasNext()) {
                UserAdminData nextuser = (UserAdminData) i.next();
                user = new UserView(nextuser);
                user.setSortBy(this.sortby);
                users.add(user);
            }

            Collections.sort(users);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @param user DOCUMENT ME!
     */
    public void addUser(UserView user) {
        user.setSortBy(this.sortby);
        users.add(user);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int size() {
        return users.size();
    }

    /**
     * DOCUMENT ME!
     */
    public void clear() {
        this.users.clear();
    }

    // Private fields
    private ArrayList users;
    private SortBy sortby;
}
