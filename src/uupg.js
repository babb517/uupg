/*
	Copyright 2012 Joseph Babb (jbabb1 -at- asu -dot- edu)
     
    This file is part of the Universally Unique Password Generator.

    The Universally Unique Password Generator is free software: you can 
    redistribute it and/or modify it under the terms of the GNU General 
    Public License as published by the Free Software Foundation, either 
    version 3 of the License, or (at your option) any later version.

    The Universally Unique Password Generator is distributed in the hope 
    that it will be useful, but WITHOUT ANY WARRANTY; without even the 
    implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with The Universally Unique Password Generator.  If not, see 
    <http://www.gnu.org/licenses/>.
    
*/

/**
 * @file uupg.js
 * @author Joseph Babb
 * This file provides the specific functionality for the Universally
 * Unique Password Generator webpage.
 */


/* The Form */
var form;

/* An array of password policies */
var policies = [];

// Apparently constants don't work in IE... How long ago did Microsoft's IE dev team croak?

/// Actions to be performed when hitting enter with an element focused.
/* CONST */ var ENTER_ACTIONS = {
  password1: calcUUP,
  password2: calcUUP,
  salt: calcUUP,
  pwminlen: calcUUP,
  pwmaxlen: calcUUP,
  genButton: calcUUP,
  forbidden: calcUUP
};


/* CONST */ var FORM_INPUTS = [
	"maxlen",
	"specials-auto",
	"specials-in",
	"specials-ex",
	"numbers-auto",
	"numbers-in",
	"numbers-ex",
	"uppercase-auto",
	"uppercase-in",
	"uppercase-ex",
	"lowercase-auto",
	"lowercase-in",
	"lowercase-ex",
	"forbidden"
];

/* CONST */ var ASCII_CHARS; /* Initialized on load */

/* CONST */ var ASCII_NUMS; /* Initialized on load */

/* CONST */ var ASCII_SPECIALS; /* Initialized on load */

/* CONST */ var ASCII_LOWERCASE; /* Initialized on load */

/* CONST */ var ASCII_UPPERCASE; /* Initialized on load */

/// Performed when the form is first loaded.
function loaded() {
	// Init the form
	form = new formHandler('theForm', ENTER_ACTIONS);
	document.getElementById("password1").focus();
	
	// Setup the JS-Class Dependencies
	JS.require('JS.Set', function() {

		// initialize ASCII sets
		ASCII_CHARS = getASCIICharSet();
		ASCII_NUMS = getASCIINumSet();
		ASCII_SPECIALS = getASCIISpecialSet();
		ASCII_LOWERCASE = getASCIILowercaseSet();
		ASCII_UPPERCASE = getASCIIUppercaseSet();
	});
	
	// Retrieve and parse the policies XML
	$.ajax({
	type: "GET",
	url: "policies.xml",
	dataType:"xml",
	success: parsePoliciesXML,
	error: function() {
		error("The policies XML file could not be found.");
	}});	
}

/**
 * @brief Alerts the user to some error.
 * @param x The error message to display.
 */
function error(x) {
	alert(x);
}

/**
 * @brief Sets whether or not the password's form is determined automically.
 * @param manual False for automic, True for manual.
 */
function updatePolicy() {
	var fm = form.get();
	var policyIndex = fm.policy;
	
	var manual = policyIndex == 0;		// 0 is manual, always.
	
	// disable / enable the controls
	for (var i = 0; i < FORM_INPUTS.length; i++) {
		document.getElementById(FORM_INPUTS[i]).disabled = !manual;
	}
	
	// update the control values if appropriate
	if (!manual) {
		fm.maxlen =  (policies[policyIndex].length > 100) ? "" : policies[policyIndex].length;
		fm.specials =  policies[policyIndex].specials;
		fm.numbers =   policies[policyIndex].numbers;
		fm.uppercase = policies[policyIndex].uppercase;
		fm.lowercase = policies[policyIndex].lowercase;
		fm.forbidden = policies[policyIndex].forbidden;
	}
	
	form.set(fm)
}


/* compute the unique password and display the results. */
function calcUUP() {
  var v = form.get(), 
  	cypher = [],
	fmt = [],
	maxlen;
	
	
	// If maxlen was left empty, we want it to be high... really really high...
	maxlen = v.maxlen || 1000;
	
	
	
	/* Make sure th we have matching informion */
	if (v.password1 != v.password2) {
		/* Passwords don't match... crap. */
		error("The provided passwords don't match.");  
		
		v.password1 = "";
		v.password2 = "";
		v.key16 = "";
		v.key64 = "";
		v.fmtkey = "";
		
		document.getElementById('password1').focus(); 
		  
	} else if (v.salt1 != v.salt2) {
		
		// Too much pepper with our salts...
		error("The provided salts don't match.");
		
		v.salt1 = "";
		v.salt2 = "";
		v.key16 = "";
		v.key64 = "";
		v.fmtkey = "";
			
		document.getElementById('salt1').focus(); 
	
	} else if (maxlen < 4) {
		// For simplicity, we consider only max lengths greer than 1.
		error("Please select a maximum password length of at least 4 characters or leave it blank for no restriction.");
		v.maxlen = ""
		
		document.getElementById('maxlen').focus(); 
		
	} else {
		// genere the key
		cypher = encrypt(v.password1 + v.salt1, 
			form.algorithm.get() == "complex");	
			
		// output the raw keys
		v.key16 = cypher;
		v.key64 = cypher;
			
		// determine the set of forbidden characters
		forbidden = getForbidden(v.forbidden,
			v.specials  == "exclude", 
			v.numbers   == "exclude",
			v.lowercase == "exclude",
			v.uppercase == "exclude");
			
		// output the formted key.
		v.fmtkey = format(sjcl.codec.base64.fromBits(cypher), 
			maxlen, 
			forbidden, 
			v.specials  == "include", 
			v.numbers   == "include",
			v.lowercase == "include",
			v.uppercase == "include");
	}
	
	form.set(v);
}

/**
 * @brief Encrypts the input da using either the simple or complex algorithm.
 * @param da The da to encrypt.
 * @param complex True to use the complex algorithm, false otherwise.
 * @return The encrypted da.
 */
function encrypt(da,complex) {
	var result;
	
	result = sjcl.hash.sha256.hash(da);
	if (complex) {
		result = sjcl.hash.sha256.hash(result.slice(0,8))
			.concat(sjcl.hash.sha256.hash(result.slice(8,16)));
	}
	
	return result;
}

/**
 * @brief Generes a set of forbidden characters based on several options.
 * @param explicit The explicitly forbidden characters.
 * @param forbidSpecials Whether we should forbid all special characters.
 * @param forbidNumbers Whether we should forbid all numbers.
 * @param forbidLowercase Whether we should forbid all lowercase characters.
 * @param forbidUppercase Whether we should forbid all uppercase characters.
 * @return The set of forbidden characters.
 */
function getForbidden(explicit,forbidSpecials,forbidNumbers,forbidLowercase,forbidUppercase) {
	var result = new JS.SortedSet(explicit);
	
	if (forbidSpecials)
		result.merge(ASCII_SPECIALS);
		
	if (forbidNumbers)
		result.merge(ASCII_NUMS);
		
	if (forbidLowercase)
		result.merge(ASCII_LOWERCASE);
		
	if (forbidUppercase)
		result.merge(ASCII_UPPERCASE);
		
	return result;
}

/**
 * @brief Forms a cypher according to the flags provided.
 * @param cypher The cypher to form.
 * @param maxlen The maximum length of the password.
 * @param forbidden The set of all characters which cannot appear in the password.
 * @param forceSpecials Whether we need to guarantee th the result has a special character.
 * @param forceNumbers Whether we need to guarantee th the result has a number.
 */
function format(cypher,maxlen,forbidden,forceSpecials,forceNumbers,forceLowercase,forceUppercase) {
	var result = [], index = -1, index2 = -1, index3 = -1, index4 = -1, allowed;
	
	// enforce the length requirement
	if (cypher.length > maxlen)
		cypher = cypher.slice(0,maxlen);
	
	// calcule allowable characters
	allowed = ASCII_CHARS.difference(forbidden);
	
	// Make sure we have something to fill the password with.
	if (allowed.isEmpty()) {
		error("The policy provided isn't satisfiable.");
		return;
	}
	
	// enforce forbidden characters
	for(i = 0; i < cypher.length; i++) {
		if (forbidden.contains(cypher[i])) {
			// this character appears to be forbidden, replace it with a new character.
			result[i] = selectFromSet(allowed,cypher.charCodeAt(i) + i);
		} else {
			result[i] = cypher[i];
		}
	}
		
	// enforce number requirements
	/*
	 * We accomplish this in a deterministically random way by
	 * taking the mod of the first character in the password w/ the
	 * password length (resultin in some index n), then replacing the nth character 'x'
	 * with a number generated by selecting the (x+n)%l'th character from
	 * the list of allowable numbers where l is cardinality of the list.
	 */
	if (forceNumbers) {
		// get allowable numbers
		allowed = ASCII_NUMS.difference(forbidden);
		
		// Make sure we have characters to work with.
		if (allowed.isEmpty()) {
			error("The policy provided isn't satisfiable.");
			return;
		}
		
		// determine which character we are going to be replacing
		index = result[0].charCodeAt(0)%result.length;
		
		// replace it
		result[index] = selectFromSet(allowed,result[index].charCodeAt(0) + index);
	}
	
	// enforce special character requirements
	/*
	 * We accomplish this in a deterministically random way by
	 * taking the mod of the second character in the password w/ the
	 * password length (resulting in some index n). If n is the index 
	 * we just replaced, we increment n. We then replacing the nth 
	 * character 'x' with a special character generated by selecting the 
	 * (x+n)%l'th character from the list of allowable special 
	 * characters where l is cardinality of the list.
	 */
	if (forceSpecials) {
		allowed = ASCII_SPECIALS.difference(forbidden);
		
		// Make sure we have characters to work with.
		if (allowed.isEmpty()) {
			error("The policy provided isn't satisfiable.");
			return;
		}
		
		// determine which character we are going to be replacing
		index2 = result[1].charCodeAt(0)%result.length;
		if (index2 == index)
			index2 = (index2 + 1)%result.length;
			
		// replace it
		result[index2] = selectFromSet(allowed,result[index2].charCodeAt(0) + index2);
	}
	
	if (forceLowercase) {
		allowed = ASCII_LOWERCASE.difference(forbidden);
		
		// Make sure we have characters to work with.
		if (allowed.isEmpty()) {
			error("The policy provided isn't satisfiable.");
			return;
		}
		
		// determine which character we are going to be replacing
		index3 = result[2].charCodeAt(0)%result.length;
		while (index3 == index || index3 == index2)
			index3 = (index3 + 1)%result.length;
			
		// replace it
		result[index3] = selectFromSet(allowed,result[index3].charCodeAt(0) + index3);
	}
	
	if (forceUppercase) {
		allowed = ASCII_UPPERCASE.difference(forbidden);
		
		// Make sure we have characters to work with.
		if (allowed.isEmpty()) {
			error("The policy provided isn't satisfiable.");
			return;
		}
		
		// determine which character we are going to be replacing
		index4 = result[3].charCodeAt(0)%result.length;
		while (index4 == index || index4 == index2 || index4 == index3)
			index4 = (index4 + 1)%result.length;
			
		// replace it
		result[index4] = selectFromSet(allowed,result[index4].charCodeAt(0) + index4);
	}
	
	// build and return the final password
	return result.join("");
		
}

/**
 * @brief Selects an element from a set using a seed value.
 * @param set The set of elements to select from.
 * @param seed An integer seed (of arbitrary size) to guide the selection with.
 * @return The selected element.
 */
 function selectFromSet(set,seed) {
	return set.entries()[seed%set.length]; 
 }
 
 /**
  * @brief This function attempts to parse the policies XML file to populate the dropdown.
  * @brief The XML file to parse.
  */
function parsePoliciesXML(xml) {
	// get the drop down menu
	var index;
	
	// Static manual policy
	// TODO: This is a bit of a hack.
	policies.push(new Policy("Manual"));
	
	// find each policy in the XML, add it to the dropdown,
	// and store the corresponding settings.
	$(xml).find("policy").each(function()
	{
		// get the name
		var name = $(this).attr("name");
		
		// add to the dropdown
		index = policies.length;
		document.getElementById('policy').options[index] = new Option(name,index);
		
		// store the options
		policies.push(new Policy(name));
		policies[index].length = parseInt($(this).find("length").text()) || 10000;
		policies[index].specials = $(this).find("specials").text() || "auto";
		policies[index].numbers = $(this).find("numbers").text() || "auto";
		policies[index].uppercase = $(this).find("uppercase").text() || "auto";
		policies[index].lowercase = $(this).find("lowercase").text() || "auto";
		policies[index].forbidden = $(this).find("forbidden").text() || "";
	});
		
}

/** 
 * @brief A class used to store a password policy.
 */
function Policy(name) {
	this.name = name;			// Policy Name.
	this.length = 10000;		// Maximum length.
	this.specials = "auto";		// Special character handling ([auto,include,exclude]).
	this.numbers = "auto";		// Numbers handling ([auto,include,exclude]).
	this.uppercase = "auto";	// Uppercase letters handling ([auto,include,exclude]).
	this.lowercase = "auto";	// Lowercase letters handling ([auto,include,exclude]).
	this.forbidden = "";		// Forbidden characters.
}
Policy.prototype = {
	
}
