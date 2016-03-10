/*
 * Copyright 2015 Demandware Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.demandware.appsec.secure.manipulation;

import java.io.IOException;
import java.io.Writer;

import com.demandware.appsec.secure.manipulation.impl.ManipulationUtils;

/**
 * Base implementation of a Manipulator (handles both filtering and encoding).
 * Provides common functionality for character/string manipulations and
 * bounds checking. Manipulators primarily implement "getCorrectCharacter" to
 * determine any Character changes necessary based on Manipulator details.
 *
 * @author Chris Smith
 */
public abstract class AbstractManipulator
{

	/**
	 * The "flavor" of a Manipulator. This option allows Manipulators to
	 * provide more granular control over a specific context.
	 */
    protected final IManipulateOption manipulatorOption;

    /**
     * Every Manipulator must have a corresponding ManipulateOption which
     * contains various options for sub-configuration of a Manipulator
     * @param manipulatorOption the {@link IManipulateOption} to use 
     */
    protected AbstractManipulator( IManipulateOption manipulatorOption )
    {
        this.manipulatorOption = manipulatorOption;
    }

    /**
     * A primary target for a Manipulator. filter removes any offending
     * characters from the given string
     * @param input the string to filter
     * @return a filtered string based on the manipulator implementation
     */
    protected String filter( String input )
    {
        StringBuilder sb = new StringBuilder( input.length() );
        for ( int i = 0; i < input.length(); i++ )
        {
            Character c = input.charAt( i );
            String corr = getCorrectCharacter( c );
            if ( ManipulationUtils.isSame( c, corr ) )
            {
                sb.append( c );
            }
        }
        return sb.toString();
    }

    /**
     * A primary target for a Manipulator. filter removes any offending
     * characters from the given string and writes to the given Writer
     * @param input the string to filter
     * @param writer a Writer to write output to
     * @throws IOException if the writer throws an IOException
     */
    protected void filter( String input, Writer writer ) throws IOException
    {
        for ( int i = 0; i < input.length(); i++ )
        {
            Character c = input.charAt( i );
            String corr = getCorrectCharacter( c );
            if ( ManipulationUtils.isSame( c, corr ) )
            {
                writer.write( c );
            }
        }
    }

    /**
     * A primary target for a Manipulator. encode modifies offending
     * characters to their "safe" equivalents
     * @param input the string to encode
     * @return an encoded string based on the manipulator implementation
     */
    protected String encode( String input )
    {
        //length * 3 is a best guess
        StringBuilder sb = new StringBuilder( input.length() * 3 );
        for ( int i = 0; i < input.length(); i++ )
        {
            char c = input.charAt( i );
            sb.append( getCorrectCharacter( c ) );
        }
        return sb.toString();
    }


    /**
     * A primary target for a Manipulator. encode modifies offending
     * characters to their "safe" equivalents and writes to the given Writer
     * @param input the string to encode
     * @param writer a Writer to write output to
     * @throws IOException if the writer throws an IOException
     */
    protected void encode( String input, Writer writer ) throws IOException
    {
        for ( int i = 0; i < input.length(); i++ )
        {
            char c = input.charAt( i );
            writer.write( getCorrectCharacter( c ) );
        }
    }

    /**
     * Given a character, do any defined, necessary manipulations to the
     * character and return its corrected, possibly manipulated version
     * @param c a single character to manipulate based on implementation
     * @return the corrected string version of the input character
     */
    protected abstract String getCorrectCharacter( Character c );

}
