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
package org.ejbca.scp.publisher;

import java.util.Vector;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.IdentityRepository;

public class ScpPublisherIdentityRepository implements IdentityRepository {
            
    private final Vector<Identity> identities = new Vector<>();
    
    // there is only one CryptoToken + KeyPair used for auth
    public ScpPublisherIdentityRepository(ScpPublisherIdentity scpPublisherIdentity) {
        identities.add(scpPublisherIdentity);
    }

    @Override
    public String getName() {
        return "ScpPublisherIdentityRepository";
    }

    @Override
    public int getStatus() {
        return IdentityRepository.RUNNING;
    }

    @Override
    public Vector<Identity> getIdentities() {
        return identities;
    }

    @Override
    public boolean add(byte[] identity) {
        return true;
    }

    @Override
    public boolean remove(byte[] blob) {
        return false;
    }

    @Override
    public void removeAll() {        
    }

}
