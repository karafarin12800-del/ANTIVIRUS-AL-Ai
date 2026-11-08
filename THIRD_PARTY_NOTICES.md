# Third-party notices

## WithSecure Labs IOCs — FallSpy YARA rule

Adapted metadata and literal indicator strings from:

- Repository: https://github.com/WithSecureLabs/iocs
- Pinned commit: 1a8384468dd292c6d2c5114c32e42dc0da1f5ae1
- Original source: GREYVIBE/greyvibe.yara, rule WITHSECURELABS_Fallspy (source excerpt referenced at lines 121–139)
- Author: WithSecure
- Source rule ID: 8d0823be-3a64-5e2d-995c-0b2fccf77a98

Copyright (c) [2022], [WithSecure Oyj]

BSD 2-Clause License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Adaptation note

This project stores the source rule's 10 literal indicators and its 4-of-10 grouping threshold. The current app matcher does not enforce YARA `fullword` boundaries, so the adapted rule is reported only as suspicious/candidate evidence, not confirmed malware. No malware sample or payload is included.
