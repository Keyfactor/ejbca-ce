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

/* version: $Id$ */

"use strict";

// Executed when the document had been loaded
document.addEventListener("DOMContentLoaded", function(event) {
    console.log("Document loaded.");
    jsTouchUpDocument();
    // Auto fokus first found element with this tag on page load (JSF2.0 does not support HTML5 attributes)
	forEachInputElementByStyleClass("jsAutoFocusOnce", function(inputField) {
		inputField.focus();
		return true;
	});
    new SessionKeepAlive("sessionKeepAliveLink");
}, false);

function jsTouchUpDocument() {
    // Hide elements that should not be shown when JS is enabled
	forEachInputElementByStyleClass("jsHide", function(inputField) {
		inputField.style.display = "none";
	});
	// Use title as HTML5 placeholder for elements marked with the style class (JSF2.0 does not support HTML5 attributes)
	forEachInputElementByStyleClass("jsTitleAsPlaceHolder", function(inputField) {
		inputField.placeholder = inputField.title;
		inputField.title = "";
	});
};

/** Keep JSF session alive by polling back-end before the session has expired */
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
                setTimeout(instance.poll, instance.timeToNextCheckInMs);
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
        setTimeout(this.poll, this.timeToNextCheckInMs);
    } else {
        console.log("Unable to find link element with id " + linkElementId + ". SessionKeepAlive will not be enabled.");
    }
};

/** Process the callback on each input element that matches the provided style class. */
function forEachInputElementByStyleClass(styleClassName, callback) {
	var inputFields = document.getElementsByTagName("input");
	for (var i = 0; i<inputFields.length; i++) {
		if (inputFields[i].className) {
			var styleClasses = inputFields[i].className.split(' ');
			for (var j = 0; j<styleClasses.length; j++) {
				if (styleClasses[j]==styleClassName) {
					// Invoke the callback with the matching element. If it returns true we stop looking for more elements.
					if (callback(inputFields[i])) {
						return;
					}
					break;
				}
			}
		}
	}
}

/** Can be invoked on AJAX requests to indicate that a background operation is running. */
function onAjaxEvent(data, elementId) {
    if (data.status == "begin") {
        document.getElementById(elementId).style.opacity = "0.2";
    } else if (data.status == "success") {
        document.getElementById(elementId).style.opacity = "1.0";
    }
}
/** Can be invoked on AJAX requests to indicate that an error has occurred. */
function onAjaxError(data, elementId) {
	console.log("onAjaxError: " + data.errorMessage);
    document.getElementById(elementId).style.opacity = "0.2";
}
