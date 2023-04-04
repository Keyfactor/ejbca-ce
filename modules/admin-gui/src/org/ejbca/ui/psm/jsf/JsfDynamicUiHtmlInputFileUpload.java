package org.ejbca.ui.psm.jsf;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.faces.component.html.HtmlInputFile;
import javax.faces.event.AbortProcessingException;
import javax.faces.event.ValueChangeEvent;
import javax.faces.event.ValueChangeListener;

import org.apache.log4j.Logger;
import org.cesecore.util.ui.DynamicUiComponent;
import org.cesecore.util.ui.DynamicUiProperty;

public class JsfDynamicUiHtmlInputFileUpload extends HtmlInputFile implements DynamicUiComponent, PropertyChangeListener {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(JsfDynamicUiHtmlInputFileUpload.class);

    /** DynamicUIProperty reference. */
    private DynamicUiProperty<?> dynamicUiProperty;

    /**
     * Default constructor.
     */
    public JsfDynamicUiHtmlInputFileUpload() {
        super();
    }
    
    /**
     * Sets the dynamic UI property reference.
     * @param property the dynamic UI property.
     */
    void setDynamicUiProperty(final DynamicUiProperty<?> property) {
        this.dynamicUiProperty = property;
        this.dynamicUiProperty.addDynamicUiComponent(this);
        addValueChangeListener(new ValueChangeListener() {
            
            @Override
            public void processValueChange(ValueChangeEvent event) throws AbortProcessingException {
                if (log.isTraceEnabled()) {
                    log.trace("Property change event for dynamic UI property " + (dynamicUiProperty != null ? dynamicUiProperty.getName()
                            : null) + " fired: " + event);
                }
            }
        });
    }
    
    @Override
    public void updateValueRange() {
        // No implemented.
    }
    
    @Override
    public void propertyChange(final PropertyChangeEvent event) {
        if (log.isTraceEnabled()) {
            log.trace("Property change event for dynamic UI property " + (dynamicUiProperty != null ? dynamicUiProperty.getName()
                    : null) + " fired: " + event);
        }
    }

}
