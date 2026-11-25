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

package org.casbin.jcasbin.persist.file_adapter;

import org.apache.commons.io.IOUtils;
import org.casbin.jcasbin.exception.CasbinAdapterException;
import org.casbin.jcasbin.exception.CasbinPolicyFileNotFoundException;
import org.casbin.jcasbin.model.Model;
import org.casbin.jcasbin.persist.Adapter;
import org.casbin.jcasbin.persist.Helper;
import org.casbin.jcasbin.util.Util;

import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
public class FileAdapter implements Adapter {
    private String filePath;
    private boolean readOnly = false;
    private ByteArrayInputStream byteArrayInputStream;

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param filePath the path of the policy file.
     */
    public FileAdapter(String filePath) {
        this.filePath = filePath;
    }

    /**
     * FileAdapter is the constructor for FileAdapter.
     *
     * @param inputStream the policy file.inputStream
     */
    public FileAdapter(InputStream inputStream) {
        readOnly = true;
        try {
            byteArrayInputStream = new ByteArrayInputStream(IOUtils.toByteArray(inputStream));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("File adapter init error");
        }
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    @Override
    public void loadPolicy(Model model) {
        if (filePath != null && !"".equals(filePath)) {
            try (FileInputStream fis = new FileInputStream(filePath)) {
                loadPolicyData(model, Helper::loadPolicyLine, fis);
            } catch (IOException e) {
                throw new CasbinAdapterException("Load policy file error", e.getCause());
            }
        }
        if (byteArrayInputStream != null) {
            loadPolicyData(model, Helper::loadPolicyLine, byteArrayInputStream);
        }
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    @Override
    public void savePolicy(Model model) {
        if (byteArrayInputStream != null && readOnly) {
            throw new CasbinAdapterException("Policy file can not write, because use inputStream is readOnly");
        }
        if (filePath == null || "".equals(filePath) || !new File(filePath).exists()) {
            throw new CasbinPolicyFileNotFoundException("invalid file path: " + filePath);
        }

        List<String> policy = new ArrayList<>();
        policy.addAll(getModelPolicy(model, "p"));
        policy.addAll(getModelPolicy(model, "g"));

        savePolicyFile(String.join("\n", policy));
    }

    private List<String> getModelPolicy(Model model, String ptype) {
        List<String> policy = new ArrayList<>();
        Optional.ofNullable(model.model.get(ptype)).ifPresent(entry -> entry.forEach((k, v) -> {
            List<String> p = v.policy.parallelStream().map(x -> policyLine(k, x)).collect(Collectors.toList());
            policy.addAll(p);
        }));
        return policy;
    }

    // Policy lines are loaded one physical line at a time, so a field must not contain a line break.
    // Fields containing commas or double quotes are quoted so they load back as one field.
    private static String policyLine(String ptype, List<String> rule) {
        List<String> fields = new ArrayList<>(rule.size() + 1);
        fields.add(csvField(ptype));
        for (String field : rule) {
            if (field != null && (field.indexOf('\n') >= 0 || field.indexOf('\r') >= 0)) {
                throw new CasbinAdapterException("invalid policy field " + field + ": line breaks are not allowed");
            }
            fields.add(csvField(field));
        }
        return Util.arrayToString(fields);
    }

    private static String csvField(String field) {
        if (field == null || (field.indexOf(',') < 0 && field.indexOf('"') < 0)) {
            return field;
        }
        return '"' + field.replace("\"", "\"\"") + '"';
    }

    private void loadPolicyData(Model model, Helper.loadPolicyLineHandler<String, Model> handler, InputStream inputStream) {
        try {
            List<String> lines = IOUtils.readLines(inputStream, Charset.forName("UTF-8"));
            lines.forEach(x -> handler.accept(x, model));
        } catch (UncheckedIOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy load error");
        }
    }

    private void savePolicyFile(String text) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            IOUtils.write(text, fos, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy save error");
        }
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    @Override
    public void addPolicy(String sec, String ptype, List<String> rule) {
        String ruleText = System.lineSeparator() + policyLine(ptype, rule);
        if (byteArrayInputStream != null && readOnly) {
            throw new CasbinAdapterException("Policy file can not write, because use inputStream is readOnly");
        }
        try (FileOutputStream fos = new FileOutputStream(filePath, true)) {
            IOUtils.write(ruleText, fos, Charset.forName("UTF-8"));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy add error");
        }
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    @Override
    public void removePolicy(String sec, String ptype, List<String> rule) {
        String ruleText = policyLine(ptype, rule);
        if (byteArrayInputStream != null && readOnly) {
            throw new CasbinAdapterException("Policy file can not write, because use inputStream is readOnly");
        }
        try {
            List<String> lines = IOUtils.readLines(new FileInputStream(filePath), Charset.forName("UTF-8"));
            lines.removeIf(line -> line.replaceAll("\\s", "").equals(ruleText.replaceAll("\\s", "")));
            savePolicyFile(String.join("\n", lines));
        } catch (IOException e) {
            e.printStackTrace();
            throw new CasbinAdapterException("Policy remove error");
        }
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    @Override
    public void removeFilteredPolicy(String sec, String ptype, int fieldIndex, String... fieldValues) {
        throw new UnsupportedOperationException("not implemented");
    }
}
