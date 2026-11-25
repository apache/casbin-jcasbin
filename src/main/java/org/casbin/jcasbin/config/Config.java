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

package org.casbin.jcasbin.config;

import org.casbin.jcasbin.exception.CasbinConfigException;
import org.casbin.jcasbin.util.Util;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class Config {
    private static final String DEFAULT_SECTION = "default";
    private static final String DEFAULT_COMMENT = "#";
    private static final String DEFAULT_COMMENT_SEM = ";";

    private ReentrantLock lock = new ReentrantLock();

    // Section:key=value
    private Map<String, Map<String, String>> data;

    /**
     * Config represents the configuration parser.
     */
    public Config() {
        data = new HashMap<>();
    }

    /**
     * newConfig create an empty configuration representation from file.
     *
     * @param confName the path of the model file.
     * @return the constructor of Config.
     */
    public static Config newConfig(String confName) {
        Config c = new Config();
        c.parse(confName);
        return c;
    }

    /**
     * newConfigFromText create an empty configuration representation from text.
     *
     * @param text the model text.
     * @return the constructor of Config.
     */
    public static Config newConfigFromText(String text) {
        Config c = new Config();
        try {
            c.parseBuffer(new BufferedReader(new StringReader(text)));
        } catch (IOException e) {
            throw new CasbinConfigException(e.getMessage(), e.getCause());
        }
        return c;
    }

    /**
     * addConfig adds a new section->key:value to the configuration.
     */
    private boolean addConfig(String section, String option, String value) {
        if (section.equals("")) {
            section = DEFAULT_SECTION;
        }

        if (!data.containsKey(section)) {
            data.put(section, new HashMap<>());
        }

        boolean ok = data.get(section).containsKey(option);
        data.get(section).put(option, value);
        return !ok;
    }

    private void parse(String fname) {
        lock.lock();
        try (FileInputStream fis = new FileInputStream(fname)) {
            BufferedReader buf = new BufferedReader(new InputStreamReader(fis));
            parseBuffer(buf);
        } catch (IOException e) {
            throw new CasbinConfigException(e.getMessage(), e.getCause());
        } finally {
            lock.unlock();
        }
    }

    private void parseBuffer(BufferedReader buf) throws IOException {
        String section = "";
        int lineNum = 0;
        String line;

        while (true) {
            lineNum++;

            if ((line = buf.readLine()) != null) {
                if ("".equals(line)) {
                    continue;
                }
            } else {
                break;
            }


            line = line.trim();
            if (line.startsWith(DEFAULT_COMMENT)) {
                continue;
            } else if (line.startsWith(DEFAULT_COMMENT_SEM)) {
                continue;
            } else if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length() - 1);
            } else {
                line = removeComment(line);

                String[] optionVal = line.split("=", 2);
                if (optionVal.length != 2) {
                    throw new IllegalArgumentException(String.format("parse the content error : line %d , %s = ? ", lineNum, optionVal[0]));
                }
                String option = optionVal[0].trim();
                String value = optionVal[1].trim();
                if (value.endsWith("\\")) {
                    value = value.substring(0, value.length() - 1);
                    while ((line = buf.readLine()) != null && line.endsWith("\\")) {
                        lineNum++;
                        line = line.trim();
                        value = value.concat(line.substring(0, line.length() - 1));
                    }
                    if (line != null) {
                        lineNum++;
                        if (line.endsWith("\\")) {
                            line = line.substring(0, line.length() - 1);
                        }
                        line = line.trim();
                        value = value.concat(line);
                    }
                }
                addConfig(section, option, value);
            }
        }
    }

    // A comment marker inside a quoted string is part of the value.
    private static String removeComment(String line) {
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"' || c == '\'') {
                i = Util.stringLiteralEnd(line, i) - 1;
            } else if (c == DEFAULT_COMMENT.charAt(0) || c == DEFAULT_COMMENT_SEM.charAt(0)) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    public boolean getBool(String key) {
        return Boolean.parseBoolean(get(key));
    }

    public int getInt(String key) {
        return Integer.parseInt(get(key));
    }

    public float getFloat(String key) {
        return Float.parseFloat(get(key));
    }

    public String getString(String key) {
        return get(key);
    }

    public String[] getStrings(String key) {
        String v = get(key);
        if (v.equals("")) {
            return null;
        }
        return v.split(",");
    }

    public void set(String key, String value) {
        lock.lock();
        if (key.length() == 0) {
            lock.unlock();
            throw new IllegalArgumentException("key is empty");
        }

        String section = "";
        String option;

        String[] keys = key.toLowerCase().split("::");
        if (keys.length >= 2) {
            section = keys[0];
            option = keys[1];
        } else {
            option = keys[0];
        }

        addConfig(section, option, value);
        lock.unlock();
    }

    public String get(String key) {
        String section;
        String option;

        String[] keys = key.toLowerCase().split("::");
        if (keys.length >= 2) {
            section = keys[0];
            option = keys[1];
        } else {
            section = DEFAULT_SECTION;
            option = keys[0];
        }

        boolean ok = data.containsKey(section) && data.get(section).containsKey(option);
        if (ok) {
            return data.get(section).get(option);
        } else {
            return "";
        }
    }
}
