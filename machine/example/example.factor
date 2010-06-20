USING: accessors fry http.machine http.machine.data
http.machine.dispatch http.machine.resource
io.servers.connection kernel namespaces threads ;
IN: http.machine.example

SINGLETON: example-resource

<PRIVATE

: produce-text-content ( -- content )
    "Hello " [ "World " [ "!" f <stream-body> ] <stream-body> ] <stream-body> ;

: produce-html-content ( -- content )
    "<html><title>Factor Machine Example</title><body><h1>Hello World!</h1></body></html>" ;

PRIVATE>

M: example-resource content-types-provided
    drop {
        { "text/plain" [ produce-text-content ] }
        { "text/html" [ produce-html-content ] } } ;

! M: example-resource allowed-methods
!    drop { "POST" "PUT" "OPTIONS" } ;


: start-machine-example ( -- )
    <machine-dispatcher>
        #{ "*" "example" "*" } example-resource add-rule
    <machine> 8080 >>insecure
    [ machine-server set-global ]
    [ '[ _ start-server ] in-thread ] bi ;

: stop-machine-example ( -- )
    machine-server get stop-server ;