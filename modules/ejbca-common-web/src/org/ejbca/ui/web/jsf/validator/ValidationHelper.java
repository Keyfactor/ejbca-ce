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
package org.ejbca.ui.web.jsf.validator;

import javax.faces.component.UIComponent;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * A utility class for JSF validation.
 *
 * @version $Id$
 */
public class ValidationHelper {

    /***
     * This method checks the UIComponent whether it contains validation preconditions or not. Validation precondition attributes
     * in priority order are:
     * <ul>
     *     <li>validationCondition - defines explicit flag for validation: true - must validate, false - skip the validation;</li>
     *     <li>validationTriggerIds - defines the binding between action-button and validated UIComponent.</li>
     * </ul>
     * If validation preconditions are not set this method returns 'true'.
     *
     * <br/><hr/>
     *
     * <h3>Example 1:</h3>
     * JSF page code:<br/>
     * <code>
     *     ...<br/>
     *     &lt;h:selectOneListbox id="selectorId"<br/>
     *                            value="#{myMBean.selectedValue}"<br/>
     *                            validator="<b>MyValidatorWithConditionalUse</b>" &gt;<br/>
     *                            ...<br/>
     *     &lt;/h:selectOneListbox&gt;<br/>
     * </code>
     * <br/>
     * Within this setup this method will return 'true'.
     *
     * <br/><hr/>
     *
     * <h3>Example 2:</h3>
     * JSF page code:<br/>
     * <code>
     *     ...<br/>
     *     &lt;h:selectOneListbox id="selectorId"<br/>
     *                            value="#{myMBean.selectedValue}"<br/>
     *                            validator="<b>MyValidatorWithConditionalUse</b>" validationCondition="<b>false</b>" &gt;<br/>
     *                            ...<br/>
     *     &lt;/h:selectOneListbox&gt;<br/>
     * </code>
     * <br/>
     * Within this setup this method will return 'false'.
     *
     * <br/><hr/>
     *
     * <h3>Example 3:</h3>
     * JSF page code:<br/>
     * <code>
     *     ...<br/>
     *     &lt;h:selectOneListbox id="selectorId"<br/>
     *                            value="#{myMBean.selectedValue}"<br/>
     *                            validator="<b>MyValidatorWithConditionalUse</b>" validationTriggerIds="<b>editButton</b>;<b>cloneButton</b>" &gt;<br/>
     *                            ...<br/>
     *     &lt;/h:selectOneListbox&gt;<br/>
     *     &lt;h:inputText id="inputId"<br/>
     *                     value="#{myMBean.inputValue}"<br/>
     *                     validator="<b>MyValidatorWithConditionalUse</b>" validationTriggerIds="<b>addButton</b>;<b>cloneButton</b>" &gt;<br/>
     *     &lt;h:inputText id="inputId2"<br/>
     *                     value="#{myMBean.inputValue2}"<br/>
     *                     validator="<b>MyValidatorWithConditionalUse</b>" &gt;<br/>
     *     ...<br/>
     *     &lt;h:commandButton id="<b>addButton</b>"<br/>
     *                         action="#{myMBean.actionAdd}"<br/>
     *                         value="Add"/ &gt;<br/>
     *     &lt;h:commandButton id="<b>editButton</b>"<br/>
     *                         action="#{myMBean.actionEdit}"<br/>
     *                         value="Edit"/ &gt;<br/>
     *     &lt;h:commandButton id="<b>cloneButton</b>"<br/>
     *                         action="#{myMBean.actionClone}"<br/>
     *                         value="Clone"/ &gt;<br/>
     * </code>
     * <br/>
     * Within this setup this method will return:
     * <ul>
     *     <li>
     *         Add button is triggered (id 'addButton'):
     *         <ul>
     *             <li>'false' for 'selectOneListbox' element;</li>
     *             <li>'true' for 'inputText' element with id 'inputId';</li>
     *             <li>'true' for 'inputText' element with id 'inputId2'.</li>
     *         </ul>
     *     </li>
     *     <li>
     *         Edit button is triggered (id 'editButton'):
     *         <ul>
     *             <li>'true' for 'selectOneListbox' element;</li>
     *             <li>'false' for 'inputText' element with id 'inputId';</li>
     *             <li>'true' for 'inputText' element with id 'inputId2'.</li>
     *         </ul>
     *     </li>
     *     <li>
     *         Clone button is triggered (id 'cloneButton'):
     *         <ul>
     *             <li>'true' for 'selectOneListbox' element;</li>
     *             <li>'true' for 'inputText' element with id 'inputId';</li>
     *             <li>'true' for 'inputText' element with id 'inputId2'.</li>
     *         </ul>
     *     </li>
     * </ul>
     *
     * @param facesContext Faces context.
     * @param uiComponent UI Component.
     *
     * @return a boolean flag for validation processing by validator, 'true' - should continue with validation logic; 'false' - should skip validation logic.
     */
    public static boolean matchConditionalValidation(final FacesContext facesContext, final UIComponent uiComponent) {
        // Check whether explicit validation condition is set
        final Object uiComponentValidationConditionObject = uiComponent.getAttributes().get("validationCondition");
        if(uiComponentValidationConditionObject != null) {
            return Boolean.valueOf(uiComponentValidationConditionObject.toString());
        }
        // Check whether this UIComponent requires for validation by originator trigger
        final Object uiComponentValidationTriggerIdsObject = uiComponent.getAttributes().get("validationTriggerIds");
        if (uiComponentValidationTriggerIdsObject != null) {
            final List<String> validationTriggerIds = Arrays.asList(((String) uiComponentValidationTriggerIdsObject).split(";"));
            final ExternalContext externalContext = facesContext.getExternalContext();
            // Compare request parameters for matching trigger id
            for (final Map.Entry<String, String[]> requestParameters : externalContext.getRequestParameterValuesMap().entrySet()) {
                // Key might be 'someId' or 'someContainer:someId'
                final String fullId = requestParameters.getKey();
                final String lastId = (fullId.lastIndexOf(':') == -1 ? null : fullId.substring(fullId.lastIndexOf(':') + 1));
                if(validationTriggerIds.contains(fullId) || (lastId != null && validationTriggerIds.contains(lastId))) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

}
