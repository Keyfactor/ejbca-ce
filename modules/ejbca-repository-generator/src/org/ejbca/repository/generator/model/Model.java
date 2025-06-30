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

package org.ejbca.repository.generator.model;

import org.ejbca.repository.generator.util.CompareUtil;
import org.ejbca.repository.generator.util.JsonUtil;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Model implements Serializable {

    private List<Entity> entities;

    public Model() {
        entities = new ArrayList<Entity>();
    }

    public Model(List<Entity> entities) {
        this.entities = entities;
    }

    public List<Entity> getEntities() {
        return entities;
    }

    public void setEntities(List<Entity> entities) {
        this.entities = entities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass().equals(o.getClass())) {
            return false;
        }
        Model model = (Model) o;
        return CompareUtil.equals(entities, model.entities);
    }

    @Override
    public int hashCode() {
        return toString().hashCode();
    }

    @Override
    public String toString() {
        return JsonUtil.toJson(this);
    }
}
