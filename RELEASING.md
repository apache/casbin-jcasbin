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

Use Java 8 and Maven 3.9.x. Prepare the release changes in one PR, then
verify its actual merged commit and CI. Java imports stay `org.casbin.jcasbin`;
Maven coordinates are `org.apache.casbin:jcasbin:X.Y.Z`.

## Release checklist

1. Confirm the release manager's signing key is in the project KEYS file and
   the ASF Nexus profile covers `org.apache.casbin`. Keep private Maven settings
   outside Git, using server ID `apache.releases.https`. The Apache parent POM
   provides the staging and snapshot URLs; do not override them. Signing,
   Nexus access and ASF dist access are separate permissions.
2. Create an unused `vX.Y.Z-rcN` tag at the reviewed merged commit. Download the
   workflow's tar.gz and ZIP source packages and SHA-512 files. Check them against
   the tag and build a disposable extraction as described in BUILDING.md.
   Keep the original archives: some tests rewrite example policies.
3. Review the source and generated main/sources/Javadoc JARs, flattened POM,
   legal files and documentation resources. Resolve any identified release
   blockers. Javadoc licensing is being reviewed separately; this Maven route
   change does not clear that question or require a newer documentation JDK.
4. From a fresh extraction of the same source, build, sign and upload Maven
   artifacts to ASF review staging with the standard release profile:

   ```sh
   mvn -B -ntp clean deploy -Papache-release -Drevision=X.Y.Z
   ```

   Use your private settings with `-s /path/to/settings.xml` if needed. Do not
   skip tests or signing for a real release. The parent profile signs the main,
   sources and Javadoc JARs and resolved POM. Source-release assembly/checksum
   executions are disabled because the tagged source archives from step 2 are
   the vote originals; do not create another source archive from test-modified
   files. Sign those original tar.gz/ZIP files separately and stage them with
   their signatures and SHA-512 files under a new ASF dev RC directory.
5. Inspect the actual Nexus repository ID and artifacts, then close it for
   review. Independently download all JARs/POM/signatures, verify KEYS,
   signatures, hashes, GAV, legal material and correspondence with the source.
   Record named source and binary review. Check remote state before retrying;
   never overwrite a candidate or drop someone else's repository.
6. Start fresh project/PPMC and IPMC votes with the exact source tag/commit,
   ASF dev source URL, closed Maven repository URL, KEYS and verification
   results. Link the dev ballot/result in the general request, and count the
   two bodies separately. Cancelled RC votes cannot be reused.
7. After both approvals, promote the voted source archives to ASF release
   distribution and release the same closed Nexus repository. Promotion does
   not rebuild Maven files. Verify public downloads and Maven resolution.
   Push `vX.Y.Z` at the reviewed RC commit only after source promotion: its
   workflow verifies and reuses the promoted ASF originals for GitHub Release,
   with no Maven rebuild or deployment. Complete the download page and announcement.

For an unsigned local check of the release profile, use
`mvn -B -ntp clean verify -Papache-release -Drevision=X.Y.Z -Dgpg.skip=true`.
This is not a signing or staging test. Ordinary development still uses
BUILDING.md and does not need the release profile.

References: [Apache parent POM](https://maven.apache.org/pom/asf/),
[ASF Maven guide](https://infra.apache.org/publishing-maven-artifacts.html),
[ASF release policy](https://www.apache.org/legal/release-policy.html),
[Incubation policy](https://incubator.apache.org/policy/incubation.html#releases).
