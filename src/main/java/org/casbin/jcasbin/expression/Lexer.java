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

package org.casbin.jcasbin.expression;

import java.util.ArrayList;
import java.util.List;

class Lexer {
    enum Kind {
        NUMBER, STRING, IDENTIFIER, OPERATOR, EOF
    }

    static class Token {
        final Kind kind;
        final String text;
        final Object value;
        final int position;

        Token(Kind kind, String text, Object value, int position) {
            this.kind = kind;
            this.text = text;
            this.value = value;
            this.position = position;
        }

        boolean is(String operator) {
            return kind == Kind.OPERATOR && text.equals(operator);
        }

        @Override
        public String toString() {
            return kind == Kind.EOF ? "end of expression" : "'" + text + "'";
        }
    }

    private static final String[] OPERATORS = {
        "**", "==", "!=", ">=", "<=", "=~", "!~", "&&", "||", "<<", ">>", "??",
        "+", "-", "*", "/", "%", ">", "<", "!", "~", "&", "|", "^", "?", ":", "(", ")", "[", "]", ","
    };

    private final String source;
    private int pos;

    private Lexer(String source) {
        this.source = source;
    }

    static List<Token> tokenize(String source) {
        Lexer lexer = new Lexer(source);
        List<Token> tokens = new ArrayList<>();
        Token token;
        do {
            token = lexer.next();
            tokens.add(token);
        } while (token.kind != Kind.EOF);
        return tokens;
    }

    private Token next() {
        while (pos < source.length() && Character.isWhitespace(source.charAt(pos))) {
            pos++;
        }
        if (pos >= source.length()) {
            return new Token(Kind.EOF, "", null, pos);
        }

        char c = source.charAt(pos);
        if (Character.isDigit(c)) {
            return number();
        }
        if (c == '\'' || c == '"') {
            return string(c);
        }
        if (Character.isJavaIdentifierStart(c)) {
            return identifier();
        }
        for (String op : OPERATORS) {
            if (source.startsWith(op, pos)) {
                Token token = new Token(Kind.OPERATOR, op, null, pos);
                pos += op.length();
                return token;
            }
        }
        throw new ExpressionException("unexpected character '" + c + "' at position " + pos + " in: " + source);
    }

    private Token number() {
        int start = pos;
        boolean decimal = false;
        while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
            pos++;
        }
        if (pos + 1 < source.length() && source.charAt(pos) == '.' && Character.isDigit(source.charAt(pos + 1))) {
            decimal = true;
            pos++;
            while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                pos++;
            }
        }
        if (pos < source.length() && (source.charAt(pos) == 'e' || source.charAt(pos) == 'E')) {
            int mark = pos;
            pos++;
            if (pos < source.length() && (source.charAt(pos) == '+' || source.charAt(pos) == '-')) {
                pos++;
            }
            if (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                decimal = true;
                while (pos < source.length() && Character.isDigit(source.charAt(pos))) {
                    pos++;
                }
            } else {
                pos = mark;
            }
        }
        String text = source.substring(start, pos);
        Object value;
        if (decimal) {
            value = Double.parseDouble(text);
        } else {
            try {
                value = Long.parseLong(text);
            } catch (NumberFormatException e) {
                value = Double.parseDouble(text);
            }
        }
        return new Token(Kind.NUMBER, text, value, start);
    }

    private Token string(char quote) {
        int start = pos;
        pos++;
        StringBuilder sb = new StringBuilder();
        while (pos < source.length()) {
            char c = source.charAt(pos);
            if (c == quote) {
                pos++;
                return new Token(Kind.STRING, source.substring(start, pos), sb.toString(), start);
            }
            if (c == '\\' && pos + 1 < source.length()) {
                char e = source.charAt(pos + 1);
                pos += 2;
                switch (e) {
                    case 'n': sb.append('\n'); break;
                    case 't': sb.append('\t'); break;
                    case 'r': sb.append('\r'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case '\\': sb.append('\\'); break;
                    case '\'': sb.append('\''); break;
                    case '"': sb.append('"'); break;
                    case 'u':
                        if (pos + 4 <= source.length()) {
                            try {
                                sb.append((char) Integer.parseInt(source.substring(pos, pos + 4), 16));
                                pos += 4;
                                break;
                            } catch (NumberFormatException ignored) {
                            }
                        }
                        sb.append("\\u");
                        break;
                    default:
                        // Keep unknown escapes such as \d as written, so regex patterns work.
                        sb.append('\\').append(e);
                }
                continue;
            }
            sb.append(c);
            pos++;
        }
        throw new ExpressionException("unterminated string starting at position " + start + " in: " + source);
    }

    private Token identifier() {
        int start = pos;
        pos++;
        while (pos < source.length()) {
            char c = source.charAt(pos);
            if (Character.isJavaIdentifierPart(c)) {
                pos++;
            } else if (c == '.' && pos + 1 < source.length() && Character.isJavaIdentifierStart(source.charAt(pos + 1))) {
                pos += 2;
            } else {
                break;
            }
        }
        String text = source.substring(start, pos);
        return new Token(Kind.IDENTIFIER, text, null, start);
    }
}
