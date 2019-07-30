function csi(id, uri, menuElement) {
	var xhq = false;
	// For WebKit and Firefox browsers
	if (window.XMLHttpRequest) {
		try {
			xhq = new XMLHttpRequest();
		} catch (e) {
			xhq = false;
		}
	} else if (window.ActiveXObject) {
		// For Internet Explorer
		try {
			xhq = new ActiveXObject("Msxml2.XMLHTTP");
		} catch (e) {
			try {
				xhq = new ActiveXObject("Microsoft.XMLHTTP");
			} catch (e) {
				xhq = false;
			}
		}
	}
	var element = document.getElementById(id);
	if (!element) {
		alert("Bad id " + id + "passed to clientSideInclude."
				+ "You need a div or span element "
				+ "with this id in your page.");
		return;
	}

	if (xhq) {
		xhq.open('GET', uri, false);
		// FIXME (pbi) CHROME since v5 does not support local file access
		try {
			xhq.send(null);
			element.innerHTML = xhq.responseText;
		} catch (e) {
			xhq = false;
		}
	}
	if (xhq == false) {
		element.innerHTML = "<div id='paragraph'><h1>Failure</h1> "
				+ "<p>Sorry, your browser does not support "
				+ "XMLHTTPRequest objects or it is not able to load "
				+ "local files. This page has only been tested on "
				+ "Firefox (Linux and Windows). Other compatible "
				+ "browsers may also exist.</p>"
				+ "<p>To make this page work in Chrome you can launch "
				+ "it with the flag <i>--allow-file-access-from-files</i> "
				+ "enabled to allow it reading from local files.</p>"
				+ "<p>You may still look at the Protocol "
				+ "Specification and the License text, which are "
				+ "included as PDF files.</p></div>";
	}
	
	// remove highlighting from all menu items except for the selected one
	var menuItem = document.getElementsByClassName('menuItem, selected');
	for (i = 0; i < menuItem.length; i++) {
		var menuItemI = menuItem[i];
		menuItemI.className = "menuItem";
	}
	menuElement.className = "menuItem, selected";
}
