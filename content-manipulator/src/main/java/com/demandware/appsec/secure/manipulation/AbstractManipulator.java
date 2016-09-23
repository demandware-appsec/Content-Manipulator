/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;

/**
 * Base implementation of a Manipulator (handles both filtering and encoding). Provides common functionality for
 * character/string manipulations and bounds checking. Manipulators primarily implement "getCorrectCharacter" to
 * determine any Character changes necessary based on Manipulator details.
 *
 * @author Chris Smith
 */
public abstract class AbstractManipulator
{

    /**
     * The "flavor" of a Manipulator. This option allows Manipulators to provide more granular control over a specific
     * context.
     */
    protected final IManipulateOption manipulatorOption;

    /**
     * Every Manipulator must have a corresponding ManipulateOption which contains various options for sub-configuration
     * of a Manipulator
     * 
     * @param manipulatorOption the {@link IManipulateOption} to use
     */
    protected AbstractManipulator( IManipulateOption manipulatorOption )
    {
        this.manipulatorOption = manipulatorOption;
    }

    /**
     * A primary target for a Manipulator. filter removes any offending characters from the given string
     * 
     * @param input the string to filter
     * @return a filtered string based on the manipulator implementation or null, if the input is null
     */
    protected String filter( String input )
    {
        if ( input == null )
        {
            return null;
        }

        StringBuilder sb = new StringBuilder( input.length() );

        try
        {
            filterInternal( input, sb );
        }
        catch ( IOException e )
        {
            // throw as unchecked as StringBuilder shouldn't have any IOExceptions
            throw new UncheckedIOException( e );
        }

        return sb.toString();
    }

    /**
     * A primary target for a Manipulator. filter removes any offending characters from the given string and writes to
     * the given Writer. If the provided input is null, no content is written to the Writer
     * 
     * @param input the string to filter
     * @param writer a Writer to write output to
     * @throws IOException if the writer throws an IOException
     * @throws IllegalArgumentException if the writer is null
     */
    protected void filter( String input, Writer writer )
        throws IOException, IllegalArgumentException
    {
        if ( input == null )
        {
            return;
        }

        if ( writer == null )
        {
            throw new IllegalArgumentException( "Writer cannot be null" );
        }

        filterInternal( input, writer );

    }

    /**
     * A primary target for a Manipulator. encode modifies offending characters to their "safe" equivalents
     * 
     * @param input the string to encode
     * @return an encoded string based on the manipulator implementation or null, if the input is null
     */
    protected String encode( String input )
    {
        if ( input == null )
        {
            return null;
        }

        // length * 3 is a best guess
        StringBuilder sb = new StringBuilder( input.length() * 3 );
        try
        {
            encodeInternal( input, sb );
        }
        catch ( IOException e )
        {
            // throw as unchecked as StringBuilder shouldn't have any IOExceptions
            throw new UncheckedIOException( e );
        }
        return sb.toString();
    }

    /**
     * A primary target for a Manipulator. encode modifies offending characters to their "safe" equivalents and writes
     * to the given Writer. If the provided input is null, no content is written to the Writer
     * 
     * @param input the string to encode
     * @param writer a Writer to write output to
     * @throws IOException if the writer throws an IOException
     * @throws IllegalArgumentException if the writer is null
     */
    protected void encode( String input, Writer writer )
        throws IOException, IllegalArgumentException
    {
        if ( input == null )
        {
            return;
        }

        if ( writer == null )
        {
            throw new IllegalArgumentException( "Writer cannot be null" );
        }

        encodeInternal( input, writer );
    }

    /**
     * Given a character, do any defined, necessary encodings to the input string and append it to the output object
     * 
     * @param input the string to encode
     * @param output the object to append the encoded version of the string to
     * @throws IOException if any IOExceptions occur in the subclass
     */
    protected abstract void encodeInternal( String input, Appendable output )
        throws IOException;

    /**
     * Given a character, do any defined, necessary filterings to the input string and append it to the output object
     * 
     * @param input the string to encode
     * @param output the object to append the encoded version of the string to
     * @throws IOException if any IOExceptions occur in the subclass
     */
    protected abstract void filterInternal( String input, Appendable output )
        throws IOException;

}
