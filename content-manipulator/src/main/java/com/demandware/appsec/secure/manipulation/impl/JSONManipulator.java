/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation.impl;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * JSONManipulator handles all content related to JavaScript Object Notation code
 *
 * @author Chris Smith
 */
public class JSONManipulator
    extends AbstractManipulator
{

    static enum JSONManipulatorOption
        implements IManipulateOption
    {
        // These values should be slash escaped
        JSON_VALUE( '\b', '\t', '\n', '\f', '\r', '"', '\\', '/' ),;

        private final Character[] escape;

        private JSONManipulatorOption( Character... escape )
        {
            this.escape = escape;
        }

        public Character[] getEscapeCharacters()
        {
            return this.escape;
        }
    }

    JSONManipulator( JSONManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        JSONManipulatorOption opt = (JSONManipulatorOption) this.manipulatorOption;

        // if the character is alphanumeric, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        // if the character should be escaped, do it
        // this disallows users from escaping JSON and writing HTML or JS code
        else if ( ManipulationUtils.isInList( c, opt.getEscapeCharacters() ) )
        {
            correctedCharacter = ManipulationUtils.slashEscapeChar( c );
        }
        // otherwise hex-encode and pad with \u0000
        else
        {
            String hex = ManipulationUtils.getHexForCharacter( c );
            String pad = "0000".substring( hex.length() );
            correctedCharacter = "\\u" + pad + hex;
        }

        return correctedCharacter;
    }
}
