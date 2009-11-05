package org.ejbca.core.ejb;

/**
 * This class is the central location to store the internal
 * names of various entities, and these internal names are later
 * mapped to the JNDI names in the deployment environment. Any change
 * here should also be reflected in the deployment descriptors.
 */
public interface JNDINames {

    /**
     * This is the datasource definition used through the whole EJBCA app.
     */
    String DATASOURCE = "java:comp/env/DataSource";

}
