/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
/*
 * AddedUserMemory.java
 *
 * Created on den 27 juli 2002, 22:01
 */
package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.util.LinkedList;


/**
 * A class used to remember a RA Admins last added users. It's use is in the adduser.jsp to list
 * previously added users give the RA admins a better overlook of the his work.
 *

 * @version $Id$
 */
public class AddedUserMemory implements Serializable {

    private static final long serialVersionUID = 1864439727928588230L;

    public static final int MEMORY_SIZE = 100; // Remember the 100 last users. 

    // Private fields
    private LinkedList<UserView> memory = null;

    /**
     * Creates a new instance of AddedUserMemory
     */
    public AddedUserMemory() {
        memory = new LinkedList<UserView>();
    }

    /**
     * Used to add a user tho the memory
     *
     * @param user the UserView representation of the user to add.
     */
    public void addUser(UserView user) {
        memory.add(user);
        while (memory.size() > MEMORY_SIZE) {
            memory.removeFirst();
        }
    }

    /**
     * Used to retrieve a number of previously added users.
     *
     * @param size the size of the array of users to return
     *
     * @return the 'size' or available users in memory.
     */
    public UserView[] getUsers(int size) {
        int endindex = memory.size() - size;
        int tempsize = size;
        UserView[] returnval;

        if (endindex < 0) {
            endindex = 0;
        }

        if (size > memory.size()) {
            tempsize = memory.size();
        }

        returnval = new UserView[tempsize];

        int j = 0;

        for (int i = memory.size() - 1; i >= endindex; i--) {
            returnval[j] = memory.get(i);
            j++;
        }

        return returnval;
    }

    /**
     * Used to update the data of a user.
     *
     * @param user the stringarray representation of the user to change.
     */
    public void changeUser(UserView user) {
        // Find user in memory.
        for (int i = 0; i < memory.size(); i++) {
            if ((memory.get(i)).getUsername().equals(user.getUsername())) {
                memory.set(i, user);

                break;
            }
        }
    }

    public void removeUser(String userName) {
     // Find user in memory.
        for (int i = 0; i < memory.size(); i++) {
            if ((memory.get(i)).getUsername().equals(userName)) {
                memory.remove(i);
                break;
            }
        }
    }
  
}
