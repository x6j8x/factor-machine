USING: assocs hashtables http.machine.data http.machine.mime
kernel tools.test ;
IN: http.machine.mime.tests

[ "application/xhtml+xml" ]
[
    "application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5"
    { { "application/xhtml+xml" [ ] } { "text/plain" [ ] } } choose-media-type
] unit-test

[ "text/html" ]
[
    "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
    { { "text/html" [ ] } { "text/plain" [ ] } } choose-media-type
] unit-test

[ "text/html" ]
[
    "application/xml,application/xhtml+xml,text/*;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
    { { "text/html" [ ] } { "text/plain" [ ] } } choose-media-type
] unit-test

[ "application/jsonp" ]
[
    "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
    { { "application/jsonp" [ ] } { "application/soap" [ ] } } choose-media-type
] unit-test

[ "image/gif" ]
[
    "application/xml,application/xhtml+xml,text/html;q=0.9,image/*,text/plain,*/*;q=0.5"
    { { "text/html" [ ] } { "image/gif" [ ] } } choose-media-type
] unit-test
