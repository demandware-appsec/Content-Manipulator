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

    protected final IManipulateOption manipulatorOption;

    /**
     * Every Manipulator must have a corresponding ManipulateOption which
     * contains various options for sub-configuration of a Manipulator
     */
    protected AbstractManipulator( IManipulateOption manipulatorOption )
    {
        this.manipulatorOption = manipulatorOption;
    }

    /**
     * A primary target for a Manipulator. filter removes any offending
     * characters from the given string
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
     */
    protected abstract String getCorrectCharacter( Character c );

}
