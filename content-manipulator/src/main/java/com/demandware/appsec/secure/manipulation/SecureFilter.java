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

import com.demandware.appsec.secure.manipulation.impl.DefaultManipulationType;
import com.demandware.appsec.secure.manipulation.impl.IManipulationType;
import com.demandware.appsec.secure.manipulation.impl.ManipulatorFactory;

/**
 * SecureFilter contains many methods for manipulating untrusted data Strings
 * into RFC-Compliant Strings for a given context by removing "bad" data from
 * the untrusted data.
 *
 * @author Chris Smith
 */
public class SecureFilter
{

    /**
     * Shared method to handle filter lookup and dispatch string
     * @param type the manipulation type to use for filter lookup
     * @param input the string to filter
     * @return a properly encoded string representation of the input string
     */
	protected static String filter( IManipulationType type, String input )
    {
        AbstractManipulator enc = ManipulatorFactory.getManipulator( type );
        return enc.filter( input );
    }

    /**
     * Shared method to handle filter lookup and dispatch string to be written
     * with the given writer
     * @param type the manipulation type to use for filter lookup
     * @param input the string to filter
     * @param writer a Writer to write output to
     */
	protected static void filter( IManipulationType type, String input, Writer writer)
    {
        AbstractManipulator enc = ManipulatorFactory.getManipulator( type );
        try
        {
            enc.filter( input, writer );
        }
        catch ( IOException e )
        {
            throw new IllegalArgumentException( "An error occurred while filtering", e );
        }
    }

    /**
     * <p>
     * Filters illegal characters from a given input for use in a general HTML
     * context. E.g. text content and text attributes. This method takes the
     * UNION of allowed characters among all contexts, so may be more
     * imprecise that the more specific contexts. Generally, this method is
     * preferred unless you specifically understand the context in which
     * untrusted data will be output.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;div&gt;${SecureFilter.filterHtmlContent(unsafeData)}&lt;/div&gt;
     *
     * &lt;input value="${SecureFilter.filterHtmlContent(unsafeData)}" /&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterHtmlContent( String input )
    {
        return filter( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterHtmlContent(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterHtmlContent( String input, Writer out )
    {
        filter( DefaultManipulationType.HTML_CONTENT_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an HTML
     * Attribute guarded by a single quote. This method is preferred if you
     * understand exactly how the output of this will be used in the HTML
     * document.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;div id='${SecureFilter.filterHtmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filterd, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterHtmlInSingleQuoteAttribute( String input )
    {
        return filter( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterHtmlInSingleQuoteAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterHtmlInSingleQuoteAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.HTML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an HTML
     * Attribute guarded by a double quote. This method is preferred if you
     * understand exactly how the output of this will be used in the HTML
     * document.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;div id="${SecureFilter.filterHtmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterHtmlInDoubleQuoteAttribute( String input )
    {
        return filter( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterHtmlInDoubleQuoteAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterHtmlInDoubleQuoteAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.HTML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an HTML
     * Attribute left unguarded. This method is preferred if you understand
     * exactly how the output of this will be used in the HTML document.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;div id=${SecureFilter.filterHtmlUnquotedAttribute(unsafeData)}&gt;&lt;/div&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterHtmlUnquotedAttribute( String input )
    {
        return filter( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterHtmlUnquotedAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterHtmlUnquotedAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.HTML_UNQUOTED_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in JavaScript
     * inside an HTML context. This method takes the UNION of allowed
     * characters among the other contexts, so may be more imprecise that the
     * more specific contexts. Generally, this method is preferred unless you
     * specifically understand the context in which untrusted data will be
     * output.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureFilter.filterJavaScriptInHTML(unsafeData)}";
     * &lt;/script&gt;
     *
     * &lt;button onclick="alert('${SecureFilter.filterJavaScriptInHTML(unsafeData)}');"&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterJavaScriptInHTML( String input )
    {
        return filter( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterJavaScriptInHTML(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterJavaScriptInHTML( String input, Writer out )
    {
        filter( DefaultManipulationType.JAVASCRIPT_HTML_MANIPULATOR, input, out );
    }

    /**
     * <p>
     * Filters illegal characters from a given input for use in JavaScript
     * inside an HTML attribute. This method is preferred if you understand
     * exactly how the output of the will be used in the page
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;button onclick="alert('${SecureFilter.filterJavaScriptInAttribute(unsafeData)}');"&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterJavaScriptInAttribute( String input )
    {
        return filter( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterJavaScriptInAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterJavaScriptInAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.JAVASCRIPT_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in JavaScript
     * inside an HTML block. This method is preferred if you understand
     * exactly how the output of the will be used in the page
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;script type="text/javascript"&gt;
     *     var data = "${SecureFilter.filterJavaScriptInBlock(unsafeData)}";
     * &lt;/script&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterJavaScriptInBlock( String input )
    {
        return filter( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterJavaScriptInBlock(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterJavaScriptInBlock( String input, Writer out )
    {
        filter( DefaultManipulationType.JAVASCRIPT_BLOCK_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in JavaScript
     * inside a JavaScript source file. This method is preferred if you
     * understand exactly how the output of the will be used in the page
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;...inside foobar.js...&gt;
     * var data = "${SecureFilter.filterJavaScriptInSource(unsafeData)}";
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterJavaScriptInSource( String input )
    {
        return filter( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterJavaScriptInSource(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterJavaScriptInSource( String input, Writer out )
    {
        filter( DefaultManipulationType.JAVASCRIPT_SOURCE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in a JSON Object
     * Value to prevent escaping into a trusted context.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * var json = {"trusted_data" : SecureFilter.filterJSONValue(unsafeData)};
     * return JSON.stringify(json);
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterJSONValue( String input )
    {
        return filter( DefaultManipulationType.JSON_VALUE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterJSONValue(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterJSONValue( String input, Writer out )
    {
        filter( DefaultManipulationType.JSON_VALUE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use as a component
     * of a URI. This is equivalent to javascript's filterURIComponent and
     * does a realistic job of encoding.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;a href="http://host.com?value=${SecureFilter.filterUriComponent(unsafeData)}"/&gt;
     * </pre>
     *
     * <b>Allows:</b>
     * <pre>A-Z, a-z, 0-9, -, _, ., ~, !, *, ', (, )</pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterUriComponent( String input )
    {
        return filter( DefaultManipulationType.URI_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterUriComponent(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterUriComponent( String input, Writer out )
    {
        filter( DefaultManipulationType.URI_COMPONENT_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use as a component
     * of a URI. This is a strict filter and fully complies with RFC3986.
     * </p>
     *
     * <b>Example Usage:</b>
     * <pre>
     * &lt;a href="http://host.com?value=${SecureFilter.filterUriComponentStrict(unsafeData)}"/&gt;
     * </pre>
     *
     * <b>Allows:</b>
     * <pre>A-Z, a-z, 0-9, -, _, ., ~</pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterUriComponentStrict( String input )
    {
        return filter( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterUriComponentStrict(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterUriComponentStrict( String input, Writer out )
    {
        filter( DefaultManipulationType.URI_STRICT_COMPONENT_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in a general XML
     * context. E.g. text content and text attributes. This method takes the
     * UNION of allowed characters between the other contexts, so may be more
     * imprecise that the more specific contexts. Generally, this method is
     * preferred unless you specifically understand the context in which
     * untrusted data will be output.
     * </p>
     *
     * <b>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</b>
     * <br>
     * <b>Example Usage:</b>
     * <pre>
     * &lt;foo&gt;${SecureFilter.filterXmlContent(unsafeData)}&lt;/foo&gt;
     *
     * &lt;bar attr="${SecureFilter.filterXmlContent(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterXmlContent( String input )
    {
        return filter( DefaultManipulationType.XML_CONTENT_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterXmlContent(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterXmlContent( String input, Writer out )
    {
        filter( DefaultManipulationType.XML_CONTENT_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an XML
     * attribute guarded by a single quote. This method is preferred if you
     * understand the context in which untrusted data will be output.
     * </p>
     *
     * <b>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</b>
     * <br>
     * <b>Example Usage:</b>
     * <pre>
     * &lt;bar attr='${SecureFilter.filterXmlInSingleQuoteAttribute(unsafeData)}'&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterXmlInSingleQuoteAttribute( String input )
    {
        return filter( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterXmlInSingleQuoteAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterXmlInSingleQuoteAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.XML_SINGLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an XML
     * attribute guarded by a double quote. This method is preferred if you
     * understand the context in which untrusted data will be output.
     * </p>
     *
     * <b>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</b>
     * <br>
     * <b>Example Usage:</b>
     * <pre>
     * &lt;bar attr="${SecureFilter.filterXmlInDoubleQuoteAttribute(unsafeData)}"&gt;&lt;/bar&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterXmlInDoubleQuoteAttribute( String input )
    {
        return filter( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterXmlInDoubleQuoteAttribute(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterXmlInDoubleQuoteAttribute( String input, Writer out )
    {
        filter( DefaultManipulationType.XML_DOUBLE_QUOTE_ATTRIBUTE_MANIPULATOR, input, out );
    }


    /**
     * <p>
     * Filters illegal characters from a given input for use in an XML
     * comments. This method is preferred if you understand the context in
     * which untrusted data will be output.
     * </p>
     *
     * <b>Note: It is recommended that you use a real parser, as this method
     * can be misused, but is left here if a parser is unavailable to you</b>
     * <br>
     * <b>Example Usage:</b>
     * <pre>
     * &lt;!-- ${SecureFilter.filterXmlCommentContent(unsafeData)} --&gt;
     * </pre>
     *
     * <b>Flow:</b>
     * <ul>
     * <li>Allow AlphaNumerics and some Special characters</li>
     * <li>Remove all other characters</li>
     * </ul>
     *
     * @param input untrusted input to be filtered, if necessary
     * @return a properly filtered string for the given input
     */
    public static String filterXmlCommentContent( String input )
    {
        return filter( DefaultManipulationType.XML_COMMENT_MANIPULATOR, input );
    }

    /**
     * Writes filtered content directly to given java.io.Writer
     * See {@link #filterXmlCommentContent(String)}
     *
     * @param input untrusted input to be filtered, if necessary
     * @param out where to write the filtered output
     */
    public static void filterXmlCommentContent( String input, Writer out )
    {
        filter( DefaultManipulationType.XML_COMMENT_MANIPULATOR, input, out );
    }

    protected SecureFilter()
    {/*Cannot instantiate*/
    }
}
