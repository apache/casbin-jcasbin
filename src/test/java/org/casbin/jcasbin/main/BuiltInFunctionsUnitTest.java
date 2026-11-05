// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package org.casbin.jcasbin.main;

import org.casbin.jcasbin.expression.ExpressionFunction;
import org.casbin.jcasbin.model.FunctionMap;
import org.casbin.jcasbin.util.BuiltInFunctions;
import org.casbin.jcasbin.util.Util;
import org.testng.annotations.Test;
import org.mockito.BDDMockito;
import org.mockito.MockedStatic;

import java.util.HashMap;
import java.util.Map;

import static org.casbin.jcasbin.main.TestUtil.*;
import static org.mockito.ArgumentMatchers.*;

public class BuiltInFunctionsUnitTest {

    @Test
    public void testKeyMatchFunc() {
        testKeyMatch("/foo", "/foo", true);
        testKeyMatch("/foo", "/foo*", true);
        testKeyMatch("/foo", "/foo/*", false);
        testKeyMatch("/foo/bar", "/foo", false);
        testKeyMatch("/foo/bar", "/foo*", true);
        testKeyMatch("/foo/bar", "/foo/*", true);
        testKeyMatch("/foobar", "/foo", false);
        testKeyMatch("/foobar", "/foo*", true);
        testKeyMatch("/foobar", "/foo/*", false);
    }

    @Test
    public void testKeyMatch2Func() {
        testKeyMatch2("/foo", "/foo", true);
        testKeyMatch2("/foo", "/foo*", true);
        testKeyMatch2("/foo", "/foo/*", false);
        testKeyMatch2("/foo/bar", "/foo", false);
        testKeyMatch2("/foo/bar", "/foo*", false);
        testKeyMatch2("/foo/bar", "/foo/*", true);
        testKeyMatch2("/foobar", "/foo", false);
        testKeyMatch2("/foobar", "/foo*", false);
        testKeyMatch2("/foobar", "/foo/*", false);

        testKeyMatch2("/", "/:resource", false);
        testKeyMatch2("/resource1", "/:resource", true);
        testKeyMatch2("/myid", "/:id/using/:resId", false);
        testKeyMatch2("/myid/using/myresid", "/:id/using/:resId", true);

        testKeyMatch2("/proxy/myid", "/proxy/:id/*", false);
        testKeyMatch2("/proxy/myid/", "/proxy/:id/*", true);
        testKeyMatch2("/proxy/myid/res", "/proxy/:id/*", true);
        testKeyMatch2("/proxy/myid/res/res2", "/proxy/:id/*", true);
        testKeyMatch2("/proxy/myid/res/res2/res3", "/proxy/:id/*", true);
        testKeyMatch2("/proxy/", "/proxy/:id/*", false);

        testKeyMatch2("/alice", "/:id", true);
        testKeyMatch2("/alice/all", "/:id/all", true);
        testKeyMatch2("/alice", "/:id/all", false);
        testKeyMatch2("/alice/all", "/:id", false);

        testKeyMatch2("/alice/all", "/:/all", false);

        testKeyMatch2("engines/engine1", "*", true);
    }

    @Test
    public void testKeyMatch3Func() {
        // keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
        testKeyMatch3("/foo", "/foo", true);
        testKeyMatch3("/foo", "/foo*", true);
        testKeyMatch3("/foo", "/foo/*", false);
        testKeyMatch3("/foo/bar", "/foo", false);
        testKeyMatch3("/foo/bar", "/foo*", false);
        testKeyMatch3("/foo/bar", "/foo/*", true);
        testKeyMatch3("/foobar", "/foo", false);
        testKeyMatch3("/foobar", "/foo*", false);
        testKeyMatch3("/foobar", "/foo/*", false);

        testKeyMatch3("/", "/{resource}", false);
        testKeyMatch3("/resource1", "/{resource}", true);
        testKeyMatch3("/myid", "/{id}/using/{resId}", false);
        testKeyMatch3("/myid/using/myresid", "/{id}/using/{resId}", true);

        testKeyMatch3("/proxy/myid", "/proxy/{id}/*", false);
        testKeyMatch3("/proxy/myid/", "/proxy/{id}/*", true);
        testKeyMatch3("/proxy/myid/res", "/proxy/{id}/*", true);
        testKeyMatch3("/proxy/myid/res/res2", "/proxy/{id}/*", true);
        testKeyMatch3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
        testKeyMatch3("/proxy/", "/proxy/{id}/*", false);

        testKeyMatch3("/myid/using/myresid", "/{id/using/{resId}", false);
    }

    @Test
    public void testKeyMatch4Func() {
        // Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns.
        testKeyMatch4("/parent/123/child/123", "/parent/{id}/child/{id}", true);
        testKeyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}", false);

        testKeyMatch4("/parent/123/child/123", "/parent/{id}/child/{another_id}", true);
        testKeyMatch4("/parent/123/child/456", "/parent/{id}/child/{another_id}", true);

        testKeyMatch4("/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}", true);
        testKeyMatch4("/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}", false);
        testKeyMatch4("/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}", false);
        testKeyMatch4("/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}", false);
        testKeyMatch4("/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}", false);

        testKeyMatch4("/parent/123/child/123", "/parent/{i/d}/child/{i/d}", false);

        testKeyMatch4("/pipeline/work-order/sit/deploy", "/pipeline/work-order/*/deploy", true);
    }

    @Test
    public void testKeyMatch5Func() {
        testKeyMatch5("/alice_data/hello/123", "/alice_data/{resource}/.*", true);

        testKeyMatch5("/parent/child?status=1&type=2", "/parent/child", true);
        testKeyMatch5("/parent?status=1&type=2", "/parent/child", false);

        testKeyMatch5("/parent/child/?status=1&type=2", "/parent/child/", true);
        testKeyMatch5("/parent/child/?status=1&type=2", "/parent/child", false);
        testKeyMatch5("/parent/child?status=1&type=2", "/parent/child/", false);

        testKeyMatch5("/foo", "/foo", true);
        testKeyMatch5("/foo", "/foo*", true);
        testKeyMatch5("/foo", "/foo/*", false);
        testKeyMatch5("/foo/bar", "/foo", false);
        testKeyMatch5("/foo/bar", "/foo*", false);
        testKeyMatch5("/foo/bar", "/foo/*", true);
        testKeyMatch5("/foobar", "/foo", false);
        testKeyMatch5("/foobar", "/foo*", false);
        testKeyMatch5("/foobar", "/foo/*", false);

        testKeyMatch5("/", "/{resource}", false);
        testKeyMatch5("/resource1", "/{resource}", true);
        testKeyMatch5("/myid", "/{id}/using/{resId}", false);
        testKeyMatch5("/myid/using/myresid", "/{id}/using/{resId}", true);

        testKeyMatch5("/proxy/myid", "/proxy/{id}/*", false);
        testKeyMatch5("/proxy/myid/", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res/res2", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res/res2/res3", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/", "/proxy/{id}/*", false);

        testKeyMatch5("/proxy/myid?status=1&type=2", "/proxy/{id}/*", false);
        testKeyMatch5("/proxy/myid/", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res?status=1&type=2", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res/res2?status=1&type=2", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/myid/res/res2/res3?status=1&type=2", "/proxy/{id}/*", true);
        testKeyMatch5("/proxy/", "/proxy/{id}/*", false);
    }

    @Test
    public void testKeyGetFunc() {
        testKeyGet("/foo", "/foo", "");
        testKeyGet("/foo", "/foo*", "");
        testKeyGet("/foo", "/foo/*", "");
        testKeyGet("/foo/bar", "/foo", "");
        testKeyGet("/foo/bar", "/foo*", "/bar");
        testKeyGet("/foo/bar", "/foo/*", "bar");
        testKeyGet("/foobar", "/foo", "");
        testKeyGet("/foobar", "/foo*", "bar");
        testKeyGet("/foobar", "/foo/*", "");
    }

    @Test
    public void TestKeyGet2() {
        testKeyGet2("/foo", "/foo", "id", "");
        testKeyGet2("/foo", "/foo*", "id", "");
        testKeyGet2("/foo", "/foo/*", "id", "");
        testKeyGet2("/foo/bar", "/foo", "id", "");
        // different with KeyMatch.
        testKeyGet2("/foo/bar", "/foo*", "id", "");
        testKeyGet2("/foo/bar", "/foo/*", "id", "");
        testKeyGet2("/foobar", "/foo", "id", "");
        // different with KeyMatch.
        testKeyGet2("/foobar", "/foo*", "id", "");
        testKeyGet2("/foobar", "/foo/*", "id", "");

        testKeyGet2("/", "/:resource", "resource", "");
        testKeyGet2("/resource1", "/:resource", "resource", "resource1");
        testKeyGet2("/myid", "/:id/using/:resId", "id", "");
        testKeyGet2("/myid/using/myresid", "/:id/using/:resId", "id", "myid");
        testKeyGet2("/myid/using/myresid", "/:id/using/:resId", "resId", "myresid");

        testKeyGet2("/proxy/myid", "/proxy/:id/*", "id", "");
        testKeyGet2("/proxy/myid/", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/*", "id", "myid");
        testKeyGet2("/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id", "myid");
        testKeyGet2("/proxy/", "/proxy/:id/*", "id", "");

        testKeyGet2("/alice", "/:id", "id", "alice");
        testKeyGet2("/alice/all", "/:id/all", "id", "alice");
        testKeyGet2("/alice", "/:id/all", "id", "");
        testKeyGet2("/alice/all", "/:id", "id", "");
        testKeyGet2("/alice/all", "/:/all", "", "");
    }

    @Test
    public void TestKeyGet3() {
        // KeyGet3() is similar with KeyGet2(), except using "/proxy/{id}" instead of "/proxy/:id".
        testKeyGet3("/foo", "/foo", "id", "");
        testKeyGet3("/foo", "/foo*", "id", "");
        testKeyGet3("/foo", "/foo/*", "id", "");
        testKeyGet3("/foo/bar", "/foo", "id", "");
        testKeyGet3("/foo/bar", "/foo*", "id", "");
        testKeyGet3("/foo/bar", "/foo/*", "id", "");
        testKeyGet3("/foobar", "/foo", "id", "");
        testKeyGet3("/foobar", "/foo*", "id", "");
        testKeyGet3("/foobar", "/foo/*", "id", "");

        testKeyGet3("/", "/{resource}", "resource", "");
        testKeyGet3("/resource1", "/{resource}", "resource", "resource1");
        testKeyGet3("/myid", "/{id}/using/{resId}", "id", "");
        testKeyGet3("/myid/using/myresid", "/{id}/using/{resId}", "id", "myid");
        testKeyGet3("/myid/using/myresid", "/{id}/using/{resId}", "resId", "myresid");

        testKeyGet3("/proxy/myid", "/proxy/{id}/*", "id", "");
        testKeyGet3("/proxy/myid/", "/proxy/{id}/*", "id", "myid");
        testKeyGet3("/proxy/myid/res", "/proxy/{id}/*", "id", "myid");
        testKeyGet3("/proxy/myid/res/res2", "/proxy/{id}/*", "id", "myid");
        testKeyGet3("/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id", "myid");
        testKeyGet3("/proxy/", "/proxy/{id}/*", "id", "");

        testKeyGet3("/api/group1_group_name/project1_admin/info", "/api/{proj}_admin/info", "proj", "");
        testKeyGet3("/{id/using/myresid", "/{id/using/{resId}", "resId", "myresid");
        testKeyGet3("/{id/using/myresid/status}", "/{id/using/{resId}/status}", "resId", "myresid");

        testKeyGet3("/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res", "res3");
        testKeyGet3("/api/project1_admin/info", "/api/{proj}_admin/info", "proj", "project1");
        testKeyGet3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
            "g", "group1");
        testKeyGet3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
            "gn", "group_name");
        testKeyGet3("/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
            "proj", "project1");
    }

    @Test
    public void testRegexMatchFunc() {
        testRegexMatch("/topic/create", "/topic/create", true);
        testRegexMatch("/topic/create/123", "/topic/create", true);
        testRegexMatch("/topic/delete", "/topic/create", false);
        testRegexMatch("/topic/edit", "/topic/edit/[0-9]+", false);
        testRegexMatch("/topic/edit/123", "/topic/edit/[0-9]+", true);
        testRegexMatch("/topic/edit/abc", "/topic/edit/[0-9]+", false);
        testRegexMatch("/foo/delete/123", "/topic/delete/[0-9]+", false);
        testRegexMatch("/topic/delete/0", "/topic/delete/[0-9]+", true);
        testRegexMatch("/topic/edit/123s", "/topic/delete/[0-9]+", false);
    }

    @Test
    public void testIpMatchFunc() {
        testIpMatch("192.168.2.123", "192.168.2.0/24", true);
        testIpMatch("192.168.2.123", "192.168.3.0/24", false);
        testIpMatch("192.168.2.123", "192.168.2.0/16", true);
        testIpMatch("192.168.2.123", "192.168.2.123", true);
        testIpMatch("192.168.2.123", "192.168.2.123/32", true);
        testIpMatch("10.0.0.11", "10.0.0.0/8", true);
        testIpMatch("11.0.0.123", "10.0.0.0/8", false);
    }

    @Test
    public void testEvalFunc() {
        AbacAPIUnitTest.TestEvalRule sub = new AbacAPIUnitTest.TestEvalRule("alice", 18);
        Map<String, Object> env = new HashMap<>();
        env.put("r_sub", sub);

        testEval("r_sub.age > 0", env, null, true);
        testEval("r_sub.name == 'alice'", env, null, true);
        testEval("r_sub.name == 'bob'", env, null, false);

        Map<String, ExpressionFunction> functions = FunctionMap.loadFunctionMap().fm;
        functions.put("custom", new FunctionTest.CustomFunc());
        env.put("r_obj", "/test/url1/url2");

        testEval("r_sub.age >= 18 && custom(r_obj)", env, functions, true);
    }

    @Test
    public void testGlobMatchFunc() {
        testGlobMatch("/foo", "/foo", true);
        testGlobMatch("/foo", "/foo*", true);
        testGlobMatch("/foo", "/foo/*", false);
        testGlobMatch("/foo/bar", "/foo", false);
        testGlobMatch("/foo/bar", "/foo*", false);
        testGlobMatch("/foo/bar", "/foo/*", true);
        testGlobMatch("/foobar", "/foo", false);
        testGlobMatch("/foobar", "/foo*", true);
        testGlobMatch("/foobar", "/foo/*", false);

        testGlobMatch("/foo", "*/foo", true);
        testGlobMatch("/foo", "*/foo*", true);
        testGlobMatch("/foo", "*/foo/*", false);
        testGlobMatch("/foo/bar", "*/foo", false);
        testGlobMatch("/foo/bar", "*/foo*", false);
        testGlobMatch("/foo/bar", "*/foo/*", true);
        testGlobMatch("/foobar", "*/foo", false);
        testGlobMatch("/foobar", "*/foo*", true);
        testGlobMatch("/foobar", "*/foo/*", false);

        testGlobMatch("/prefix/foo", "*/foo", false);
        testGlobMatch("/prefix/foo", "*/foo*", false);
        testGlobMatch("/prefix/foo", "*/foo/*", false);
        testGlobMatch("/prefix/foo/bar", "*/foo", false);
        testGlobMatch("/prefix/foo/bar", "*/foo*", false);
        testGlobMatch("/prefix/foo/bar", "*/foo/*", false);
        testGlobMatch("/prefix/foobar", "*/foo", false);
        testGlobMatch("/prefix/foobar", "*/foo*", false);
        testGlobMatch("/prefix/foobar", "*/foo/*", false);

        testGlobMatch("/prefix/subprefix/foo", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foo", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foo", "*/foo/*", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foo/bar", "*/foo/*", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo*", false);
        testGlobMatch("/prefix/subprefix/foobar", "*/foo/*", false);
    }

    @Test
    public void should_logged_when_eval_given_errorExpression() {
        // given
        Map<String, Object> env = new HashMap<>();

        try (MockedStatic<Util> utilMocked = BDDMockito.mockStatic(Util.class)) {
            utilMocked.when(() -> Util.logPrintfWarn(anyString(), anyString())).thenCallRealMethod();
            // when
            BuiltInFunctions.eval("error(", env, null);
            // then
            utilMocked.verify(() -> Util.logPrintfWarn(eq("Execute 'eval' function error, nested exception is: {}"), any()));
        }
    }

}
