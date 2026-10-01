<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Releasing JCasbin

Prepare dependency, licensing and workflow changes together in one
release-preparation PR. Complete the scoped checks before requesting merge.
Use [BUILDING.md](BUILDING.md) for the full Java 8/Maven build. Release-script
tests run with `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.
The release workflows require Python 3 and GnuPG, provided by Ubuntu runners.

## Versioning

The version is **not** committed to the source tree. `pom.xml` declares
`<version>${revision}</version>` with the placeholder `0.0.0`, and the release
version comes from the git tag: `vX.Y.Z-rcN` and `vX.Y.Z` both map to Maven
version `X.Y.Z`. The Maven publish job passes `-Drevision=X.Y.Z`, and
`flatten-maven-plugin` writes the resolved version into the POM that is
deployed to Maven Central. Nothing in the repository needs to change between
releases except the tag.

## Before creating an RC tag

The Maven coordinates are `org.apache.casbin:jcasbin` starting with 1.100.0.
Java package names remain unchanged. Check the effective and flattened POMs,
README coordinates and generated JAR metadata together. Confirm that the
project's Central publishing account can administer the `org.apache.casbin`
namespace before attempting publication; permission for `org.casbin` alone
does not establish permission for the new namespace. See the migration note
in README.md for downstream dependency handling.

1. Check the latest releases/tags and choose the next `X.Y.Z`.
   Resolve relevant dependency updates and legal/source-archive findings in the
   preparation PR. The approved release scope determines which changes are included.
2. After merge, record the exact merged SHA and verify its build. Check the
   final source archive with Apache RAT and review LICENSE, NOTICE, DISCLAIMER,
   third-party material and any exclusions. New merged bytes need new evidence.
3. Confirm that a maintainer can create the tag, the release manager can sign
   and write the Casbin ASF distribution directories, and the signing public
   key is in the official Casbin KEYS file.
4. The Maven job uses existing repository secrets `GPG_PRIVATE_KEY`,
   `GPG_PASSPHRASE`, `GPG_KEY_NAME`, `OSSRH_JIRA_USERNAME` and
   `OSSRH_JIRA_PASSWORD`. The last two names are retained for compatibility:
   their values must be the Central Publisher Portal user-token username and
   password with publishing permission for `org.apache.casbin`, not old OSSRH login
   credentials. Check configuration without disclosing secret values.

## RC and community vote

Create `vX.Y.Z-rcN` at the reviewed merged SHA. The tag workflow creates a
GitHub prerelease containing:

- `apache-casbin-jcasbin-X.Y.Z-incubating-src.tar.gz` and its `.sha512`;
- `apache-casbin-jcasbin-X.Y.Z-incubating-src.zip` and its `.sha512`.

Download and verify these exact archives; independently inspect/unpack/build
them. Sign **both** archives, adding each `.asc`. Stage all six files under
`https://dist.apache.org/repos/dist/dev/incubator/casbin/jcasbin-X.Y.Z-incubating-rcN/`.
Verify the public downloads, signatures and checksums, then conduct the
applicable Casbin/Incubator votes on these immutable files. Never overwrite a
staged candidate. If candidate bytes must change, use a new RC number.

GitHub refuses creation if that Release already exists. A failed or partial
run needs its actual uploaded state inspected; do not delete and recreate a
candidate already used for voting as a retry mechanism.

## Promote and publish after approval

1. Record the successful applicable vote results. Promote the same six files
   to the ASF release directory `incubator/casbin/jcasbin-X.Y.Z-incubating/`.
2. Wait until all six files are available at
   `https://downloads.apache.org/incubator/casbin/jcasbin-X.Y.Z-incubating/`.
3. Create the final `vX.Y.Z` tag at the same reviewed RC commit. This workflow
   downloads the promoted ASF originals, verifies SHA-512 and detached
   signatures against Casbin KEYS, and compares both archive file sets with
   the tagged Git source. It does not rebuild or replace those source archives.
4. GitHub Release creation fails if the Release already exists. Maven Central
   publishing follows only after the final GitHub Release job succeeds.
   A Maven-only retry is available through **Publish Maven** on the matching
   final tag. It repeats the ASF-source verification before loading private
   signing credentials; never dispatch it from master or an RC tag. Check
   whether the Maven version already exists before retrying a failed publish.
5. Verify the published distributions, update download links, send the release
   announcement as authorized, and retain the vote/artifact evidence.

Missing ASF files, mismatched source, bad checksums or invalid signatures stop
publication. Availability in ASF's release directory is an execution gate;
the release manager remains responsible for the actual vote and promotion.
These operations require no additional source PR after the preparation merges.

References: [ASF release policy](https://www.apache.org/legal/release-policy.html)
and [Central Maven publishing](https://central.sonatype.org/publish/publish-portal-maven/).
