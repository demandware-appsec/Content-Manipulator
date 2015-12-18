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
package com.demandware.appsec.secure.manipulation.impl;

import com.demandware.appsec.secure.manipulation.AbstractManipulator;
import com.demandware.appsec.secure.manipulation.IManipulateOption;

/**
 * URIManipulator handles all content related to URIs
 *
 * @author Chris Smith
 */
public class URIManipulator
    extends AbstractManipulator
{

    static enum URIManipulatorOption
        implements IManipulateOption
    {
        //This list contains characters that are immune from modification
        //COMPONENT is a lenient list, modeled after javascript's encodeURIComponent
        COMPONENT       ( '-', '_', '.', '~', '!', '*', '\'', '(', ')' ),
        //COMPONENT_STRICT is based on the RFC
        COMPONENT_STRICT( '-', '_', '.', '~' ),
        ;

        private final Character[] immune;

        private URIManipulatorOption( Character... immune )
        {
            this.immune = immune;
        }

        public Character[] getImmuneCharacters()
        {
            return this.immune;
        }
    }

    URIManipulator( URIManipulatorOption manipulatorOption )
    {
        super( manipulatorOption );
    }

    @Override
    protected String getCorrectCharacter( Character c )
    {
        String correctedCharacter = "";
        URIManipulatorOption opt = (URIManipulatorOption) this.manipulatorOption;

        //If the character is alphanumeric, or immune, it is OK
        if ( ManipulationUtils.isAlphaNum( c ) || ManipulationUtils.isInList( c, opt.getImmuneCharacters() ) )
        {
            correctedCharacter = String.valueOf( c );
        }
        //Otherwise, Percent encode the hex representation
        else
        {
            correctedCharacter = "%" + ManipulationUtils.getHexForCharacter( c );
        }

        return correctedCharacter;
    }
}
