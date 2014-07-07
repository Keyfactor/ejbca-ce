/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.peerconnector;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Basic entity been for peer types
 * 
 * 
 *  INT4 id
    VARCHAR(25x) name
    INT4 direction (0=incoming, 1=outgoing)
    INT4 state (0=disabled, 1=enabled)
    CLOB data:
        incoming:
            last from
            last authentication token
            requested capabilities
        outgoing:
            url
            TLS settings
            initiator capabilities
    INT4 rowVersion
    CLOB rowProtection
 * 
 * @version $Id$
 *
 */
@Entity
@Table(name = "PeerData")
public class PeerData  extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 3304969435926944799L;
    private int rowVersion = 0;
    private String rowProtection;
    
    private int id;     
    private String name; 
    private int direction;
    private int state; 
    private String data; 
    
    
    public PeerData(int id, String name, int direction, int state, String data) {
        this.id = id;
        this.name = name;
        this.direction = direction;
        this.state = state;
        this.data = data;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }
    
    public int getDirection() {
        return direction;
    }

    public void setDirection(int direction) {
        this.direction = direction;
    }
    

    public int getState() {
        return state;
    }

    public void setState(int state) {
        this.state = state;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
    
    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
    
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }
    
    //
    // Start Database integrity protection methods
    //

    @Override
    protected String getProtectString(int rowversion) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
        // What is important to protect here is the data that we define
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getData()).append(getDirection()).append(getId()).append(getName()).append(getState());
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() {
        super.verifyData();
    }
    
    @Override
    public void setRowProtection(String rowProtection) {
        this.rowProtection = rowProtection;  
    }

    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Transient
    @Override
    protected String getRowId() {
        return String.valueOf(getId());
    }
    
    

}
