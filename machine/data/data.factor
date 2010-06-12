USING: accessors assocs combinators kernel namespaces calendar calendar.format 
io.encodings.utf8 arrays ;
IN: http.machine.data

SINGLETONS: static stream ;

UNION: body-option static stream ;

TUPLE: body { option body-option initial: stream } content ;

TUPLE: request-state
    socket peer ;

TUPLE: machine-request 
    method url version headers cookies host port 
    display-path path raw-path path-info path-tokens 
    app-root state metadata body ;

TUPLE: machine-response
    version code reason headers cookies encoding body ;

: <machine-response> ( -- response )
    machine-response new
    "1.1" >>version
    500 >>code
    H{ } clone >>headers
    H{ } clone >>cookies
    utf8 >>encoding ;

: <machine-request> ( -- request )
    machine-request new 
    H{ } clone >>metadata 
    request-state new >>state ;

: request ( -- request ) machine-request get ; inline

: response ( -- response ) machine-response get ; inline

: >machine-request ( request -- machine-request )
    [ <machine-request> ] dip
    {
        [ method>> >>method ]
        [ url>> >>raw-path ]
        [ version>> >>version ]
        [ header>> >>headers ]
        [ post-data>> [ static ] dip 2array >>body ]
        [ cookies>> >>cookies ]
    } cleave ;

: set-metadata ( value key -- )
    request metadata>> set-at ; inline

: get-metadata ( key -- value )
    request metadata>> at ; inline

: set-request-header ( value key -- )
    request headers>> set-at ; inline

: get-request-header ( header -- value )
    request headers>> at ; inline

: set-response-header ( value key -- )
    response headers>> set-at ; inline

: get-response-header ( header -- value )
    response headers>> at ; inline

: set-header ( request/response value key -- request/response )
    pick headers>> set-at ; inline

: header ( request/response key -- value ) swap headers>> at ;

: do-redirect? ( -- ? )
    f ;
