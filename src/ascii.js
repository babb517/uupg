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
 * @file ascii.js
 * @author Joseph Babb
 * @brief This file provides a functions used to get several common subsets of the ASCII character set.
 */

/**
 * @brief Returns the set of all ASCII printable characters.
 */
function getASCIICharSet() {
	var result = new JS.SortedSet();

	// Genere the ASCII Characters
	for (i = 32; i < 127; i++)
		result.add(String.fromCharCode(i));	
		
	return result;
}

/**
 * @brief Returns the set of all ASCII Special characters.
 */
function getASCIISpecialSet() {
	var result = new JS.SortedSet();
	
	for (i = 32; i < 48; i++)
		result.add(String.fromCharCode(i));
		
	for (i = 58; i < 65; i++)
		result.add(String.fromCharCode(i));
		
	for (i = 91; i < 97; i++)
		result.add(String.fromCharCode(i));
		
	for (i = 123; i < 127; i++)
		result.add(String.fromCharCode(i));
		
	return result;
}

/**
 * @brief Returns the set of all ASCII numbers.
 */
 function getASCIINumSet() {
	var result = new JS.SortedSet();
	
	for (i = 48; i < 58; i++)
		result.add(String.fromCharCode(i));
		
	return result;
 }
 
 /**
  * @brief Returns the set of all ASCII uppercase letters.
  */
  function getASCIIUppercaseSet() {
	var result = new JS.SortedSet();
	
	for (i = 65; i < 91; i++)
		result.add(String.fromCharCode(i));
		
	return result;
  }
  
  /**
  * @brief Returns the set of all ASCII uppercase letters.
  */
  function getASCIILowercaseSet() {
	var result = new JS.SortedSet();
	
	for (i = 97; i < 123; i++)
		result.add(String.fromCharCode(i));
		
	return result;
  }