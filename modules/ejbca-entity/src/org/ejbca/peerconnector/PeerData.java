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
package org.ejbca.peerconnector;

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
 *  
    INT4 id
    VARCHAR(25x) name
    INT4 connectorState (0=disabled, 1=enabled)
    VARCHAR(25x) url
    CLOB data:
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
    private int connectorState;
    private String url;
    private String data; 
    
    
    public PeerData() {
        super();
    }
    
    public PeerData(int id, String name, String url, int connectorState, String data) {
        super();
        this.id = id;
        this.name = name;
        this.setUrl(url);
        this.setConnectorState(connectorState);
        this.data = data;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
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
        build.append(getData()).append(getUrl()).append(getId()).append(getName()).append(getConnectorState());
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

    public int getConnectorState() {
        return connectorState;
    }

    public void setConnectorState(int connectorState) {
        this.connectorState = connectorState;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

}
