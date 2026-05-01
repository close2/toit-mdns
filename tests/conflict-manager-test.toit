// Copyright (C) 2026 Christian Loitsch.
// Use of this source code is governed by an MIT-style license that can be
// found in the LICENSE file.

import expect show *
import mdns.server.conflict_manager show ConflictManager

main:
  test-next-name-with-local-suffix
  test-next-name-with-hyphenated-local-suffix
  test-next-name-increment-with-local-suffix
  test-next-name-without-suffix
  test-next-name-with-hyphenated-name-without-suffix
  test-next-name-increment-without-suffix
  test-next-name-high-number
  print "All ConflictManager tests passed."

test-next-name-with-local-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "dummy.local"
  expect-equals "dummy-2.local" result

test-next-name-with-hyphenated-local-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "rc-test.local"
  expect-equals "rc-test-2.local" result

test-next-name-increment-with-local-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "dummy-2.local"
  expect-equals "dummy-3.local" result

test-next-name-without-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "myhost"
  expect-equals "myhost-2" result

test-next-name-with-hyphenated-name-without-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "rc-test"
  expect-equals "rc-test-2" result

test-next-name-increment-without-suffix:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "myhost-5"
  expect-equals "myhost-6" result

test-next-name-high-number:
  cm := ConflictManager
  result := cm.resolve-probing-conflict "device-99.local"
  expect-equals "device-100.local" result
