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

package org.cesecore.ui;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.JsonSerializable;

/**
 * <p>This abstract class defines the basic functionality required by a reusable JSF component,
 * whose behaviour differs from implementation to implementation, what we call a dynamic 
 * JSF component. Dynamic JSF components are used to render parts of the EJBCA web interface, 
 * such as approval profiles, approval requests and validators.</p>
 * <p>A dynamic JSF component points to a facelet which specifies how the component is
 * rendered, encapsulates the data which is displayed to the user and is responsible
 * for validating user input.</p>
 * <p>Dynamic JSF components can be serialised to and constructed from JSON objects, which
 * can be stored in a database, written to a file or sent over the network.</p>
 * <p>A dynamic JSF component is displayed in a JSF 2.0 facelet using the following piece 
 * of XHTML:
 * <pre>
 * &lt;ui:include src="#{dynamicJsfComponent.facelet}"&gt;
 *     &lt;ui:param name="component" value="#{dynamicJsfComponent}"/&gt;
 * &lt;/ui:include&gt;
 * </pre>
 * If, for example, the <code>dynamicJsfComponent</code> would be an implementation of a
 * radio group, this would render a set of radio buttons in the user's browser. You can
 * get more fine-grained control over how the component is rendered using 
 * {@link #setRenderingMode()}.</p>
 * <p>To create a new instance of a dynamic JSF component, use one of the factory methods 
 * in <code>DynamicJsfComponentFactory</code>.</p>
 * @version $Id$
 */
public abstract class DynamicJsfComponent implements JsonSerializable {
    protected JsfRenderingMode jsfRenderingMode = JsfRenderingMode.Enabled;
    protected String label;
    
    /**
     * <p>Set a value determining how the dynamic JSF component is rendered on
     * the screen.</p>
     * <p>Typical values are <code>JsfRenderingMode.Hidden</code> if the user has
     * chosen to hide the component, <code>JsfRenderingMode.Disabled</code> if the 
     * user is in view-only mode or does not have access to edit the data being displayed 
     * and <code>JsfRenderingMode.Enabled</code> if the user is in edit-mode and is 
     * allowed to change the data being displayed.</p>
     * @param jsfRenderingMode the rendering mode to use
     */
    public void setRenderingMode(final JsfRenderingMode jsfRenderingMode) {
        this.jsfRenderingMode = jsfRenderingMode;
    }
    
    /**
     * Get a value determining how the dynamic JSF component is rendered on
     * the screen. If no explicit rendering mode has been specified, the default
     * rendering mode <code>JsfRenderingMode.Enabled</code> is returned.
     * @return the rendering mode to use, default is <code>JsfRenderingMode.Enabled</code>
     */
    public JsfRenderingMode getRenderingMode() {
        return jsfRenderingMode;
    }
    
    /**
     * Set the label of this dynamic JSF component.
     * @param the new label of the component
     */
    public void setLabel(final String label) {
        this.label = label;
    }
    
    /**
     * Get the label of this dynamic JSF component. If the component does not have a
     * label, an empty string is returned.
     * @return the label of the component, never null
     */
    public String getLabel() {
        return label == null ? StringUtils.EMPTY : label;
    }
    
    /**
     * <p>Get a string containing a URI pointing to the facelet which should be used
     * to render the dynamic JSF component. Different facelets may be returned depending
     * on the rendering mode used.</p>
     * <p>The return value can be used with the JSF source attribute as follows:
     * <pre>
     * &lt;ui:include src="#{dynamicJsfComponent.facelet}"&gt;
     *     &lt;ui:param name="component" value="#{dynamicJsfComponent}"/&gt;
     * &lt;/ui:include&gt;
     * </pre>
     * Note that this object must be passed as parameter to the facelet using the 
     * <code>ui:param</code> tag as shown above.</p>
     * @return a URI pointing to the facelet which should be used
     */
    public abstract String getFacelet();

    /**
     * <p>Returns the type of implementation for this object which can be used to cast a 
     * dynamic JSF component to the correct class.</p>
     * <p>For example:
     * <pre>
     * if (dynamicJsfComponent.getType() == JsfComponentType.RadioGroup) {
     *     final JsfRadioGroup jsfRadioGroup = (JsfRadioGroup) dynamicJsfComponent;
     *     // Do something with jsfRadioGroup
     * }
     * </pre>
     * </p>
     * @return
     */
    public abstract JsfComponentType getType();
}
