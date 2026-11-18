module totp

source "src"
source "test" if test

import cstd
import std
// The CSPRNG behind generate_totp_secret. osrand is a standard-library module,
// not a name the compiler injects, so a module that calls it must name it.
import osrand

import test if test
import test_env if test
