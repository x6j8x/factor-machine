
IN: http.machine

TUPLE: machine-server < threaded-server ;

: read-http-request ( -- request )
    <machine-request> 
    read-request-line 
    read-header >>headers
    extract-host 
    extract-cookies ; 

M: http-server handle-client*
    [
        ?refresh-all
        read-http-request
        [ dispatch-request ]
        [ handle-response ] bi
    ] with-destructors ;