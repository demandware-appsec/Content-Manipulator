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
import com.demandware.appsec.secure.manipulation.impl.HTMLManipulator.HTMLManipulatorOption;
import com.demandware.appsec.secure.manipulation.impl.JSONManipulator.JSONManipulatorOption;
import com.demandware.appsec.secure.manipulation.impl.JavaScriptManipulator.JavaScriptManipulatorOption;
import com.demandware.appsec.secure.manipulation.impl.URIManipulator.URIManipulatorOption;
import com.demandware.appsec.secure.manipulation.impl.XMLManipulator.XMLManipulatorOption;

/**
 * The Default Manipulation Types are the standard manipulators bundled with 
 * this library. They pre-configure each Manipulator in preparation for use
 * with the ManipulatorFactory. 
 * 
 * @author Chris Smith
 *
 */
public enum DefaultManipulationType implements IManipulationType
{
    HTML_CONTENT_MANIPULATOR( new HTMLManipulator( HTMLManipulatorOption.CONTENT ) ),
    HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR( new HTMLManipulator( HTMLManipulatorOption.UNQUOTED_ATTRIBUTE ) ),
    HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR( new HTMLManipulator( HTMLManipulatorOption.SINGLE_QUOTE_ATTRIBUTE ) ),
    HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR( new HTMLManipulator( HTMLManipulatorOption.DOUBLE_QUOTE_ATTRIBUTE ) ),
    JAVASCRIPT_HTML_MANIPULATOR( new JavaScriptManipulator( JavaScriptManipulatorOption.HTML ) ),
    JAVASCRIPT_ATTRIBUTE_MANIPULATOR( new JavaScriptManipulator( JavaScriptManipulatorOption.ATTRIBUTE ) ),
    JAVASCRIPT_BLOCK_MANIPULATOR( new JavaScriptManipulator( JavaScriptManipulatorOption.BLOCK ) ),
    JAVASCRIPT_SOURCE_MANIPULATOR( new JavaScriptManipulator( JavaScriptManipulatorOption.SOURCE ) ),
    JSON_VALUE_MANIPULATOR( new JSONManipulator( JSONManipulatorOption.JSON_VALUE ) ),
    URI_COMPONENT_MANIPULATOR( new URIManipulator( URIManipulatorOption.COMPONENT ) ),
    URI_STRICT_COMPONENT_MANIPULATOR( new URIManipulator( URIManipulatorOption.COMPONENT_STRICT ) ),
    XML_CONTENT_MANIPULATOR( new XMLManipulator( XMLManipulatorOption.CONTENT ) ),
    XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR( new XMLManipulator( XMLManipulatorOption.SINGLE_QUOTE_ATTRIBUTE ) ),
    XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR( new XMLManipulator( XMLManipulatorOption.DOUBLE_QUOTE_ATTRIBUTE ) ),
    XML_COMMENT_MANIPULATOR( new XMLManipulator( XMLManipulatorOption.COMMENT_CONTENT ) ),
    ;

    private final AbstractManipulator manipulator;

    private DefaultManipulationType( AbstractManipulator manipulator )
    {
        this.manipulator = manipulator;
    }

    public AbstractManipulator getManipulator()
    {
        return this.manipulator;
    }
}