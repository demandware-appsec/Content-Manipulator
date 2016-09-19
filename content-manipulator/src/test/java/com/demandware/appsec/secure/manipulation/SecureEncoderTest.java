/*
 * Copyright 2015 Demandware Inc. Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.demandware.appsec.secure.manipulation;

import static org.junit.Assert.assertEquals;

import java.io.StringWriter;

import org.junit.Test;

import com.demandware.appsec.secure.manipulation.SecureEncoder;

public class SecureEncoderTest
{

    @Test
    public void CDATATest()
    {
        String CDATA1 =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( CDATA1.length() );

        assertEquals( "encodeCDATA positive test failed", CDATA1, SecureEncoder.encodeCDATAContent( CDATA1 ) );

        SecureEncoder.encodeCDATAContent( CDATA1, sw );
        assertEquals( "encodeCDATA positive test failed", CDATA1, sw.toString() );

        String CDATA2 = "foo]]]]>]]";
        sw = new StringWriter( CDATA2.length() );
        String expected = "foo]]]]>]]<![CDATA[>]]";
        assertEquals( "encodeCDATA negative test failed", expected, SecureEncoder.encodeCDATAContent( CDATA2 ) );

        SecureEncoder.encodeCDATAContent( CDATA2, sw );
        assertEquals( "encodeCDATA negative test failed", expected, sw.toString() );
    }

    @Test
    public void HTMLTest()
    {
        String htmlTest =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( htmlTest.length() * 2 );

        String htmlContent =
            "&lt;!--this! is/ a; comment: --&gt;&lt;foo attribute=value&gt;text&lt;/foo&gt;&lt;bar attribute=&quot;doublevalue&quot;&gt;text2&lt;/bar&gt;&lt;baz attribute=&#x27;singlevalue&#x27;&gt;)(*#$!@#?&lt;/baz&gt;";
        assertEquals( "encodeHTMLContent failed", htmlContent, SecureEncoder.encodeHtmlContent( htmlTest ) );

        SecureEncoder.encodeHtmlContent( htmlTest, sw );
        assertEquals( "encodeHTMLContent failed", htmlContent, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlDouble =
            "&lt;!--this! is/ a; comment: --&gt;&lt;foo attribute=value&gt;text&lt;/foo&gt;&lt;bar attribute=&quot;doublevalue&quot;&gt;text2&lt;/bar&gt;&lt;baz attribute='singlevalue'&gt;)(*#$!@#?&lt;/baz&gt;";
        assertEquals( "encodeHtmlInDoubleQuoteAttribute failed", htmlDouble,
            SecureEncoder.encodeHtmlInDoubleQuoteAttribute( htmlTest ) );

        SecureEncoder.encodeHtmlInDoubleQuoteAttribute( htmlTest, sw );
        assertEquals( "encodeHtmlInDoubleQuoteAttribute failed", htmlDouble, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlSingle =
            "&lt;!--this! is/ a; comment: --&gt;&lt;foo attribute=value&gt;text&lt;/foo&gt;&lt;bar attribute=\"doublevalue\"&gt;text2&lt;/bar&gt;&lt;baz attribute=&#x27;singlevalue&#x27;&gt;)(*#$!@#?&lt;/baz&gt;";
        assertEquals( "encodeHtmlInSingleQuoteAttribute failed", htmlSingle,
            SecureEncoder.encodeHtmlInSingleQuoteAttribute( htmlTest ) );

        SecureEncoder.encodeHtmlInSingleQuoteAttribute( htmlTest, sw );
        assertEquals( "encodeHtmlInSingleQuoteAttribute failed", htmlSingle, sw.toString() );

        sw = new StringWriter( htmlTest.length() * 2 );
        String htmlUnq =
            "&lt;!--this!&#x20;is/&#x20;a;&#x20;comment:&#x20;--&gt;&lt;foo&#x20;attribute=value&gt;text&lt;/foo&gt;&lt;bar&#x20;attribute=&quot;doublevalue&quot;&gt;text2&lt;/bar&gt;&lt;baz&#x20;attribute=&#x27;singlevalue&#x27;&gt;)(*#$!@#?&lt;/baz&gt;";
        assertEquals( "encodeHtmlUnquotedAttribute failed", htmlUnq,
            SecureEncoder.encodeHtmlUnquotedAttribute( htmlTest ) );

        SecureEncoder.encodeHtmlUnquotedAttribute( htmlTest, sw );
        assertEquals( "encodeHtmlUnquotedAttribute failed", htmlUnq, sw.toString() );

    }

    @Test
    public void XMLTest()
    {
        String xmlTest =
            "<!--this! is/ a; comment: --><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        StringWriter sw = new StringWriter( xmlTest.length() * 2 );

        String xmlContent =
            "&lt;&#x21;--this&#x21; is&#x2f; a; comment: --&gt;&lt;foo attribute&#x3d;value&gt;text&lt;&#x2f;foo&gt;&lt;bar attribute&#x3d;&quot;doublevalue&quot;&gt;text2&lt;&#x2f;bar&gt;&lt;baz attribute&#x3d;&apos;singlevalue&apos;&gt;)(&#x2a;&#x23;&#x24;&#x21;&#x40;&#x23;&#x3f;&lt;&#x2f;baz&gt;";
        assertEquals( "encodeXmlContent failed", xmlContent, SecureEncoder.encodeXmlContent( xmlTest ) );

        SecureEncoder.encodeXmlContent( xmlTest, sw );
        assertEquals( "encodeXmlContent failed", xmlContent, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlDouble =
            "&lt;&#x21;--this&#x21; is&#x2f; a; comment: --&gt;&lt;foo attribute&#x3d;value&gt;text&lt;&#x2f;foo&gt;&lt;bar attribute&#x3d;&quot;doublevalue&quot;&gt;text2&lt;&#x2f;bar&gt;&lt;baz attribute&#x3d;'singlevalue'&gt;)(&#x2a;&#x23;&#x24;&#x21;&#x40;&#x23;&#x3f;&lt;&#x2f;baz&gt;";
        assertEquals( "encodeXmlInDoubleQuoteAttribute failed", xmlDouble,
            SecureEncoder.encodeXmlInDoubleQuoteAttribute( xmlTest ) );

        SecureEncoder.encodeXmlInDoubleQuoteAttribute( xmlTest, sw );
        assertEquals( "encodeXmlInDoubleQuoteAttribute failed", xmlDouble, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlSingle =
            "&lt;&#x21;--this&#x21; is&#x2f; a; comment: --&gt;&lt;foo attribute&#x3d;value&gt;text&lt;&#x2f;foo&gt;&lt;bar attribute&#x3d;\"doublevalue\"&gt;text2&lt;&#x2f;bar&gt;&lt;baz attribute&#x3d;&apos;singlevalue&apos;&gt;)(&#x2a;&#x23;&#x24;&#x21;&#x40;&#x23;&#x3f;&lt;&#x2f;baz&gt;";
        assertEquals( "encodeXmlInSingleQuoteAttribute failed", xmlSingle,
            SecureEncoder.encodeXmlInSingleQuoteAttribute( xmlTest ) );

        SecureEncoder.encodeXmlInSingleQuoteAttribute( xmlTest, sw );
        assertEquals( "encodeXmlInSingleQuoteAttribute failed", xmlSingle, sw.toString() );

        sw = new StringWriter( xmlTest.length() * 2 );
        String xmlComment =
            "<!&#x2d;&#x2d;this! is/ a; comment: &#x2d;&#x2d;><foo attribute=value>text</foo><bar attribute=\"doublevalue\">text2</bar><baz attribute='singlevalue'>)(*#$!@#?</baz>";
        assertEquals( "encodeXmlComment failed", xmlComment, SecureEncoder.encodeXmlCommentContent( xmlTest ) );

        SecureEncoder.encodeXmlCommentContent( xmlTest, sw );
        assertEquals( "encodeXmlComment failed", xmlComment, sw.toString() );

    }

    @Test
    public void JavaScriptTest()
    {
        String javascriptTest =
            "console.log(\"Log Message!\");\r\n $(ajax).postMessage('foo.com');\nvar x = 123+14*82/12-6;";
        StringWriter sw = new StringWriter( javascriptTest.length() * 2 );

        String jsHTML =
            "console.log(\\x22Log Message!\\x22);\\r\\n $(ajax).postMessage(\\x27foo.com\\x27);\\nvar x = 123+14*82\\/12\\-6;";
        assertEquals( "encodeJavaScriptInHTML failed", jsHTML, SecureEncoder.encodeJavaScriptInHTML( javascriptTest ) );

        SecureEncoder.encodeJavaScriptInHTML( javascriptTest, sw );
        assertEquals( "encodeJavaScriptInHTML failed", jsHTML, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsAttr =
            "console.log(\\x22Log Message!\\x22);\\r\\n $(ajax).postMessage(\\x27foo.com\\x27);\\nvar x = 123+14*82/12-6;";
        assertEquals( "encodeJavaScriptInAttribute", jsAttr,
            SecureEncoder.encodeJavaScriptInAttribute( javascriptTest ) );

        SecureEncoder.encodeJavaScriptInAttribute( javascriptTest, sw );
        assertEquals( "encodeJavaScriptInAttribute failed", jsAttr, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsBlock =
            "console.log(\\\"Log Message!\\\");\\r\\n $(ajax).postMessage(\\'foo.com\\');\\nvar x = 123+14*82\\/12\\-6;";
        assertEquals( "encodeJavaScriptInBlock failed", jsBlock,
            SecureEncoder.encodeJavaScriptInBlock( javascriptTest ) );

        SecureEncoder.encodeJavaScriptInBlock( javascriptTest, sw );
        assertEquals( "encodeJavaScriptInBlock failed", jsBlock, sw.toString() );

        sw = new StringWriter( javascriptTest.length() * 2 );
        String jsSource =
            "console.log(\\\"Log Message!\\\");\\r\\n $(ajax).postMessage(\\'foo.com\\');\\nvar x = 123+14*82/12-6;";
        assertEquals( "encodeJavaScriptInSource failed", jsSource,
            SecureEncoder.encodeJavaScriptInSource( javascriptTest ) );

        SecureEncoder.encodeJavaScriptInSource( javascriptTest, sw );
        assertEquals( "encodeJavaScriptInSource failed", jsSource, sw.toString() );

    }

    @Test
    public void JSONTest()
    {
        String jsonValues = "\"}{\"CustomData\":[\"foo bar\"]}";
        StringWriter sw = new StringWriter( jsonValues.length() * 2 );

        String json = "\\\"\\u007d\\u007b\\\"CustomData\\\"\\u003a\\u005b\\\"foo\\u0020bar\\\"\\u005d\\u007d";
        assertEquals( "encodeJSONValue failed", json, SecureEncoder.encodeJSONValue( jsonValues ) );

        SecureEncoder.encodeJSONValue( jsonValues, sw );
        assertEquals( "encodeJSONValue failed", json, sw.toString() );

    }

    @Test
    public void URITest()
    {
        String URI = "?foo=bar&test=^42@314*(&SF&Ts=+~\u0732";
        StringWriter sw = new StringWriter( URI.length() * 2 );

        String uriComp = "%3ffoo%3dbar%26test%3d%5e42%40314*(%26SF%26Ts%3d%2b~%732";
        assertEquals( "encodeUriComponent failed", uriComp, SecureEncoder.encodeUriComponent( URI ) );

        SecureEncoder.encodeUriComponent( URI, sw );
        assertEquals( "encodeUriComponent failed", uriComp, sw.toString() );

        sw = new StringWriter( URI.length() * 2 );
        String uriStrict = "%3ffoo%3dbar%26test%3d%5e42%40314%2a%28%26SF%26Ts%3d%2b~%732";
        assertEquals( "encodeUriComponentStrict failed", uriStrict, SecureEncoder.encodeUriComponentStrict( URI ) );

        SecureEncoder.encodeUriComponentStrict( URI, sw );
        assertEquals( "encodeUriComponentStrict failed", uriStrict, sw.toString() );

    }

}
