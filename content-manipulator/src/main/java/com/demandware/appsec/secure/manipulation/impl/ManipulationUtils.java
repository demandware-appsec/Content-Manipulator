package com.demandware.appsec.secure.manipulation.impl;

public class ManipulationUtils {

	/**
	 * Join the given arrays, maintaining order where arr1 comes before arr2.
	 * @param arr1 a Character array to join
	 * @param arr2 a Character array to join
	 * @return null if both arrays are null, or a copy of arr1+arr2. 
	 * If only one array is null, the other array is copied only
	 */
	public static Character[] combineArrays( final Character[] arr1, final Character[] arr2 )
	{
		Character[] join;
		if( arr1 == null && arr2 == null )
		{
			return null;
		}
		
		if( arr1 == null )
		{
			join = arr2.clone();
		}
		else if( arr2 == null )
		{
			join = arr1.clone();
		} 
		else
		{
			join = new Character[ arr1.length + arr2.length ];
			System.arraycopy( arr1, 0, join, 0, arr1.length );
			System.arraycopy( arr2, 0, join, arr1.length, arr2.length );
		}
		return join;
	}

	/**
	 * An aid to filtering, isSame returns true if a given
	 * Character exactly matches a given String in size (1) and content
	 */
	public final static boolean isSame( Character c, String s )
	{
	    // length is checked as a shortcut and sanity check against
	    // "&" -> "&amp;" being equal since their first characters are equal
	    return s.length() == 1 && c.equals( s.charAt( 0 ) );
	}

	/**
	 * Converts given character to it's escaped version
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
	 * Returns true if the character is in the set of
	 * lowercase, uppercase, or numeric characters, false otherwise
	 */
	public final static boolean isAlphaNum( char c )
	{
	    return ( c <= 0x7A && c >= 0x61 ) || // lowercase
	           ( c <= 0x5A && c >= 0x41 ) || // uppercase
	           ( c <= 0x39 && c >= 0x30 );   // numbers
	}

	/**
	 * Given a char, return the Hex representation of that
	 * char (does not include 0x or similar)
	 */
	public final static String getHexForCharacter( char c )
	{
	    return Integer.toHexString( c );
	}
	
	private ManipulationUtils(){}
	
}
