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

/* javascript functions declared to "use strict" to execute in strict mode.
 * JS methods are put under the "ejbca.ra" namespace and only expose 
 * those used explicitly by the RA pages. 
 * I.e. methods has to called by ejbca.ra.toggleDetails()
 * version: $Id$ 
 */
(function() {
    "use strict";

    // Executed when the document had been loaded
    document.addEventListener("DOMContentLoaded", function(event) {
        console.log("Document loaded.");
        touchUpDocument();
        handleAutoFocus();
        new SessionKeepAlive("sessionKeepAliveLink");
    }, false);

    /** Create a file input element with id "newElementId" as child to the "appendToElementId". */
    var createInputFileElement = function(newElementId, appendToElementId, onUploadFinishedCallback) {
    	if (document.getElementById(newElementId)) {
    		console.log("ejbca.ra.createFileUploadInput: Element '" + newElementId + "' already exists.");
    		return;
    	}
    	if (!document.getElementById(appendToElementId)) {
    		console.log("ejbca.ra.createFileUploadInput: Element '" + appendToElementId + "' does not exist.");
    		return;
    	}
    	var inputFileElement = document.createElement("input");
    	inputFileElement.type = "file";
    	inputFileElement.id = newElementId;
    	inputFileElement.onchange = function() {
    		if (inputFileElement.files.length != 0) {
    			var fileReader = new FileReader();
    			fileReader.onloadend = function(event) {
    				if (event.target.readyState == FileReader.DONE) {
    					if (onUploadFinishedCallback) {
    						onUploadFinishedCallback(event.target.result);
    					}
    					inputFileElement.value = '';
    				}
    			};
    			fileReader.readAsText(inputFileElement.files[0]);
    		};
    	};
    	document.getElementById(appendToElementId).appendChild(inputFileElement);
    };

    /** Looked for tagged objects and make the page nicer when JS is available */
    var touchUpDocument = function() {
        // Hide elements that should not be shown when JS is enabled
    	forEachInputElementByTagNameAndStyleClass(["input", "label", "select"], "jsHide", function(inputField) { inputField.style.display = "none"; });
        // Show elements that should not be hidden when JS is disabled
    	forEachInputElementByTagNameAndStyleClass(["input", "label", "select"], "jsShow", function(inputField) { inputField.style.display = "inherit"; });
    	// Use title as HTML5 placeholder for elements marked with the style class (JSF2.0 does not support HTML5 attributes)
    	forEachInputElementByTagNameAndStyleClass(["input", "textarea"], "jsTitleAsPlaceHolder", function(inputField) {
    		inputField.placeholder = inputField.title;
    		inputField.title = "";
    	});
    	// Delay "keyup" events for input elements marked with the provided styleClassName. (JSF2.0 AJAX work around.)
    	forEachInputElementByTagNameAndStyleClass(["input"], "jsDelayKeyUp", function(inputField) {
    		new KeyUpEventDelay(inputField, 400);
    	});
    };

    /** Set focus to component by class names (JSF2.0 does not support HTML5 attributes like autofocus) */
    var handleAutoFocus = function() {
    	var focusElementTypes = ["a", "input", "textarea", "select"];
        // Auto focus last found element tagged "jsAutoFocusLast"
    	forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusLast", function(inputField) {
    		inputField.focus();
    		return true;
    	}, true);
        // Auto focus last found element tagged "jsAutoFocusFirst" (overriding previously set focus)
    	forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusFirst", function(inputField) {
    		inputField.focus();
    		return true;
    	});
    	// Auto focus last found element tagged "jsAutoFocusJsf" (overriding previously set focus)
    	forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusJsf", function(inputField) {
    		inputField.focus();
    		return true;
    	});
        // Auto focus first found element tagged "jsAutoFocusError" (overriding previously set focus)
    	forEachInputElementByTagNameAndStyleClass(focusElementTypes, "jsAutoFocusError", function(inputField) {
    		inputField.focus();
    		return true;
    	});
    };

    /** Process the callback on each input element that matches the provided style class. */
    function forEachInputElementByTagNameAndStyleClass(elementTagNames, styleClassName, callback, reverse) {
    	for (var k=0; k<elementTagNames.length; k++) {
    		var elementTagName = elementTagNames[k];
    		var inputFields = document.getElementsByTagName(elementTagName);
    		for (var i = (reverse?inputFields.length-1:0); (reverse?i>=0:i<inputFields.length); (reverse?i--:i++)) {
    			if (inputFields[i].className) {
    				var styleClasses = inputFields[i].className.split(' ');
    				for (var j = 0; j<styleClasses.length; j++) {
    					if (styleClasses[j]==styleClassName) {
    						//console.log("forEachInputElementByStyleClass: " + styleClassName + " → will invoke callback for '" + inputFields[i].id + "'");
    						if (callback(inputFields[i])) {
    							return;
    						}
    						//console.log("forEachInputElementByStyleClass: return was not false, will remove the class and process next one");
    						// Remove the class name to avoid processing it multiple times if this method is invoked again
    						inputFields[i].className = inputFields[i].className.replace(styleClassName, "").trim();
    						// Invoke the callback with the matching element. If it returns true we stop looking for more elements.
    						break;
    					}
    				}
    			}
    		}
    	}
    }

    /**
     * Keep JSF session alive by polling back-end before the session has expired.
     * 
     * @param linkElementId ID of a-element pointing to keep alive link.
     */
    function SessionKeepAlive(linkElementId) {
        var instance = this;
        this.timeToNextCheckInMs = 100; // Make first check after 100 ms.
        this.xmlHttpReq = new XMLHttpRequest();
        var linkComponent = document.getElementById(linkElementId);
        if (linkComponent) {
            this.link = linkComponent.getAttribute("href");
        }
        this.xmlHttpReq.onreadystatechange = function() {
            if (instance.xmlHttpReq.readyState == 4) {
                if (instance.xmlHttpReq.status == 200) {
                    instance.timeToNextCheckInMs = instance.xmlHttpReq.responseText;
                    window.setTimeout(instance.poll, instance.timeToNextCheckInMs);
            	} else {
                    console.log("SessionKeepAlive failed with HTTP status code " + instance.xmlHttpReq.status);
            	}
            }
        };
        this.poll = function() {
        	instance.xmlHttpReq.open("GET", instance.link, true);
            try {
            	instance.xmlHttpReq.send();
            } catch (exception) {
                console.log("SessionKeepAlive failed: " + exception);
            }
        };
        if (this.link) {
        	window.setTimeout(this.poll, this.timeToNextCheckInMs);
        } else {
            console.log("Unable to find link element with ID '" + linkElementId + "'. SessionKeepAlive will not be enabled.");
        }
    };

    /**
     * Delays "onkeyup" event handler invocation while additional events are triggered.
     * 
     * @param inputElement the element to wrap the onkeyup handler for
     * @param timeoutMs delay in milliseconds
     */
    function KeyUpEventDelay(inputElement, timeoutMs) {
        var instance = this;
        this.component = inputElement;
        this.originalHandler = inputElement.onkeyup;
        this.timeout = timeoutMs;
        this.timer = 0;

        this.delay = function(event) {
        	// Reschedule (prevent) any existing timeout to the original handler and schedule a new one
            window.clearTimeout(instance.timer);
            instance.timer = window.setTimeout(function() { instance.originalHandler.call(instance.component, event); }, instance.timeout);
        };
        
        if (this.originalHandler) {
        	this.component.onkeyup = this.delay;
        }
    };

    /** Can be invoked on AJAX requests to indicate that a background operation is running. */
    var onAjaxEvent = function(data, elementId) {
        if (data.status == "begin") {
            document.getElementById(elementId).style.opacity = "0.2";
        } else if (data.status == "success") {
            document.getElementById(elementId).style.opacity = "1.0";
        }
    };
    /** Can be invoked on AJAX requests to indicate that an error has occurred. */
    var onAjaxError = function(data, elementId) {
    	console.log("onAjaxError: " + data.errorMessage);
        document.getElementById(elementId).style.opacity = "0.2";
    };

    function toggleDetails(element, show, hide) {
        var detailsId = element.id + 'Details';
        //alert(detailsId);
        var details = document.getElementById(detailsId);
        if (details.style.display == 'none') {
            details.style.display = 'block';
            element.value = hide;
        } else {
            details.style.display = 'none';
            element.value = show;
        }
    }


    // Setup name space...
    window.ejbca = window.ejbca || {};
    ejbca.ra = ejbca.ra || {};
    // ...and expose API functions under this name space.
    ejbca.ra.createFileUploadInput = createInputFileElement;
    ejbca.ra.touchUpDocument = touchUpDocument;
    ejbca.ra.handleAutoFocus = handleAutoFocus;
    ejbca.ra.onAjaxEvent = onAjaxEvent;
    ejbca.ra.onAjaxError = onAjaxError;
    ejbca.ra.toggleDetails = toggleDetails;
}());
