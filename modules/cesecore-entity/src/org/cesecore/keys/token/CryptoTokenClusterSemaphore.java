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

import java.io.Serializable;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * I store a random value associated with a cryptotoken ID, used to detect
 * cryptotoken changes across JVMs.
 */
@Entity
@Table(name = "CryptoTokenClusterSemaphore")
public class CryptoTokenClusterSemaphore implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    private Integer id; // a token id
    private Long randomValue;

    public CryptoTokenClusterSemaphore() {
    }
    
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public Long getRandomValue() {
        return randomValue;
    }

    public void setRandomValue(Long randomValue) {
        this.randomValue = randomValue;
    }
}
