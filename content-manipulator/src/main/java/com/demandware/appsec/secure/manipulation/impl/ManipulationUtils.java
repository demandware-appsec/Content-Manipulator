/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation.impl;

/**
 * A set of helper methods shared across this library.
 * 
 * @author Chris Smith
 */
public class ManipulationUtils
{

    /**
     * Join the given arrays, maintaining order where arr1 comes before arr2.
     * 
     * @param arr1 a Character array to join
     * @param arr2 a Character array to join
     * @return null if both arrays are null, or a copy of arr1+arr2. If only one array is null, the other array is
     *         copied only
     */
    public static Character[] combineArrays( final Character[] arr1, final Character[] arr2 )
    {
        Character[] join;
        if ( arr1 == null && arr2 == null )
        {
            return null;
        }

        if ( arr1 == null )
        {
            join = arr2.clone();
        }
        else if ( arr2 == null )
        {
            join = arr1.clone();
        }
        else
        {
            join = new Character[arr1.length + arr2.length];
            System.arraycopy( arr1, 0, join, 0, arr1.length );
            System.arraycopy( arr2, 0, join, arr1.length, arr2.length );
        }
        return join;
    }

    /**
     * An aid to filtering, isSame returns true if a given Character exactly matches a given String in size (1) and
     * content
     * 
     * @param c a character to test against
     * @param s a string to compare to the character
     * @return true if the string describes the character exactly
     */
    public final static boolean isSame( Character c, String s )
    {
        // length is checked as a shortcut and sanity check against
        // "&" -> "&amp;" being equal since their first characters are equal
        return s.length() == 1 && c.equals( s.charAt( 0 ) );
    }

    /**
     * Converts given character to it's escaped version
     * 
     * @param c a character to possibly escape
     * @return a slash-escaped version of the character, if necessary
     */
    public final static String slashEscapeChar( Character c )
    {
        String value = null;
        switch ( c )
        {
            case '\t':
                value = "\\t";
                break;
            case '\b':
                value = "\\b";
                break;
            case '\n':
                value = "\\n";
                break;
            case '\r':
                value = "\\r";
                break;
            case '\f':
                value = "\\f";
                break;
            default:
                value = "\\" + String.valueOf( c );
                break;
        }

        return value;
    }

    /**
     * Returns true if character is found in the given list
     * 
     * @param c a character to search for
     * @param list a list to search within
     * @return true if the character exists in the list
     */
    public final static boolean isInList( Character c, Character[] list )
    {
        boolean inList = false;

        if ( list == null && c == null )
        {
            inList = true;
        }
        else if ( list == null || c == null )
        {
            inList = false;
        }
        else
        {
            for ( int i = 0; i < list.length; i++ )
            {
                if ( list[i].equals( c ) )
                {
                    inList = true;
                    break;
                }
            }
        }
        return inList;
    }

    /**
     * Checks to see if a character is alphanumeric
     * 
     * @param c a character to check against
     * @return true if the character is in the set of lowercase, uppercase, or numeric characters, false otherwise
     */
    public final static boolean isAlphaNum( char c )
    {
        return ( c <= 0x7A && c >= 0x61 ) || // lowercase
            ( c <= 0x5A && c >= 0x41 ) || // uppercase
            ( c <= 0x39 && c >= 0x30 ); // numbers
    }

    /**
     * Given a char, return the Hex representation of that char (does not include 0x or similar)
     * 
     * @param c a character to hexify
     * @return the hex string representation of the character
     */
    public final static String getHexForCharacter( char c )
    {
        return Integer.toHexString( c );
    }

    private ManipulationUtils()
    {
    }
}
