/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;

/**
 * Database representation of a CryptoToken.
 * 
 * @version $Id$
 */
@Entity
@Table(name = "CryptoTokenData")
public class CryptoTokenData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;

    private int id;            // Internal and static over time representation when referencing this token
    private String tokenName;       // The name the creator has given to token
    private String tokenType;       // Mapped to implementation class
    private long lastUpdate = 0;    // Last update to database
    private String tokenProps;      // Properties of the token
    private String tokenData;       // Raw data like a soft keystore
    private int rowVersion = 0;
    private String rowProtection;

    public CryptoTokenData(int id, String tokenName, String tokenType, long lastUpdate, Properties tokenProperties, byte[] tokenDataAsBytes) {
        setId(id);
        setTokenName(tokenName);
        setTokenType(tokenType);
        setLastUpdate(lastUpdate);
        setTokenProperties(tokenProperties);
        setTokenDataAsBytes(tokenDataAsBytes);
    }

    public CryptoTokenData() {}

    // @Id @Column
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }

    // @Column
    public String getTokenName() { return tokenName; }
    public void setTokenName(String tokenName) { this.tokenName = tokenName; }

    // @Column
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }

    // @Column
    public long getLastUpdate() { return lastUpdate; }
    public void setLastUpdate(long lastUpdate) { this.lastUpdate = lastUpdate; }

    // @Column @Lob
    public String getTokenProps() { return tokenProps; }
    public void setTokenProps(String tokenProps) { this.tokenProps = tokenProps; }

    // @Column @Lob
    public String getTokenData() { return tokenData; }
    public void setTokenData(String tokenData) { this.tokenData = tokenData; }

    // @Version @Column
    public int getRowVersion() { return rowVersion; }
    public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

    // @Column @Lob
    @Override
    public String getRowProtection() { return rowProtection; }
    @Override
    public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }
    
    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    public String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
        // What is important to protect here is the data that we define
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getId()).append(getTokenName()).append(getTokenType()).append(getLastUpdate()).append(getTokenProps()).append(getTokenData())/*.append(getCertRefs())*/;
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
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return String.valueOf(getId());
    }
    //
    // End Database integrity protection methods
    //

    @Transient
    public Properties getTokenProperties() {
        final Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(Base64.decode(getTokenProps().getBytes("UTF8"))));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return props;
    }

    @Transient
    public void setTokenProperties(final Properties props) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            props.store(baos, null);
            setTokenProps(new String(Base64.encode(baos.toByteArray(), false), "UTF8"));
            baos.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Transient
    public byte[] getTokenDataAsBytes() {
        try {
            final String data = getTokenData();
            if (data == null || data.length() == 0) {
                return new byte[0];
            }
            return Base64.decode(data.getBytes("UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Transient
    public void setTokenDataAsBytes(byte[] data) {
        if (data==null) {
            data = new byte[0];
        }
        try {
            setTokenData(new String(Base64.encode(data, false), "UTF8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }
}
