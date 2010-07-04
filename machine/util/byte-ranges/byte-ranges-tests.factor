USING: http.machine.util.byte-ranges kernel tools.test ;

IN: http.machine.util.byte-ranges.tests

[ V{ T{ byte-range f 0 20 } } ] [ 1024 "bytes=0-20" byte-ranges ] unit-test

[ V{ T{ byte-range f 1000 1024 } } ] [ 1024 "bytes=-24" byte-ranges ] unit-test

[ V{ T{ byte-range f 0 20 } T{ byte-range f 1000 1024 } } ]
[ 1024 "bytes=5-10,0-15,14-20,-24" byte-ranges ] unit-test

[ V{ T{ byte-range f 1000 1024 } } ] [ 1024 "bytes=1000-" byte-ranges ] unit-test
