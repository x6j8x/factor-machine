USING: accessors arrays assocs calendar calendar.parser calendar.format
combinators combinators.short-circuit continuations formatting
fry hashtables http.machine.data http.machine.mime
http.machine.resource http.machine.response http.machine.states
http.machine.util io io.crlf kernel locals math math.order
memoize namespaces sequences strings ;
IN: http.machine.flow

GENERIC: decide ( resource d -- )

CONSTANT: TRACE_FLOW f

<PRIVATE

: ?trace ( state -- )
    TRACE_FLOW
    [ name>> "X-Machine-Flow" append-response-header ] [ drop ] if ; inline

: decision-test ( resource ? true false -- )
    pick [ drop ] [ nip ] if nip decide ; inline

: run-decision ( resource state quot -- )
    [ ?trace ] dip [  ] swap 
    [ decision-test ] compose bi ; inline

CONSTANT: 100-CONTINUE T{ machine-response { code 100 } { version "1.1" } }

: ?expect ( -- )
    "expect" request-header "100-continue" = [
        100-CONTINUE write-response-line crlf drop flush
        "expect" request headers>> delete-at
    ] when ;

M: integer decide nip [ response ] dip >>code drop ;

M: v3b13 decide
    [ service-available? v3b12 503 ] run-decision ;

M: v3b12 decide
    [ [ request method>> ] dip known-methods member? v3b11 501 ] run-decision ;

M: v3b11 decide
    [ uri-too-long? 414 v3b10 ] run-decision ;

M: v3b10 decide ( resource d -- )
    ?trace dup [ request method>> ] dip allowed-methods
    [ nip ] [ member? ] 2bi
    [ drop v3b9 decide ]
    [
        nip "," join "Allow" set-response-header
        response 405 >>code drop
    ] if ;

M: v3b9 decide
    [ malformed-request? 400 v3b8 ] run-decision ;

M: v3b8 decide
    ?trace [  ] [ is-authorized? ] bi
    {  
        {
            [ dup string? ]
            [ nip "WWW-Authenticate" set-response-header response 401 >>code drop ]
        }
        {
            [ dup integer? ]
            [ [ drop response ] dip >>code drop ] 
        }
        {
            [ dup not ] [ 2drop response 401 >>code drop ]
        }
        [ drop v3b7 decide ]
    } cond ;

M: v3b7 decide
    [ forbidden? 403 v3b6 ] run-decision ;

M: v3b6 decide
    [ valid-content-headers? v3b5 501 ] run-decision ;

M: v3b5 decide
    [ known-content-type? v3b4 415 ] run-decision ;

M: v3b4 decide
    [ valid-entity-length? v3b3 413 ] run-decision ;

M: v3b3 decide
    ?trace request method>> "OPTIONS" = 
    [        
        options [ [ second ] [ first ] bi set-response-header ] each
    ] [ v3c3 decide ] if ;

: (content-types-provided) ( resource -- ct )
    content-types-provided >alist ;

: ?content-types-provided ( resource quot -- )
    [
        dup (content-types-provided) dup empty? 
        [ drop 503 decide ]
    ] dip if ; inline

M: v3c3 decide
    ?trace "accept" request-header
    [ v3c4 decide ] [
        [ [ nip first first accept-content-type set-tx-metadata ] ?content-types-provided ]
        [ v3d4 decide ] bi
    ] if ;

M: v3c4 decide
    ?trace "accept" request-header 
    '[ _ swap choose-media-type
        [ accept-content-type set-tx-metadata v3d4 decide ]
        [ 406 decide ] if*
    ] ?content-types-provided ;

M: v3d4 decide
    [ drop "accept-language" request-header v3d5 v3e5 ] run-decision ;

M: v3d5 decide
    [ language-available? v3e5 406 ] run-decision ;

M: v3e5 decide
    ?trace "accept-charset" request-header
    [ v3e6 decide ]
    [
        [ "*" choose-charset accept-content-charset set-tx-metadata ]
        [ v3f6 decide ] bi 
    ] if ;

M: v3e6 decide
    ?trace [  ] [ 
        "accept-charset" request-header choose-charset 
        [ accept-content-charset set-tx-metadata ] keep
        [ v3f6 decide ] [ 406 decide ] if
    ] bi ;

M: v3f6 decide
    [ drop "accept-encoding" request-header v3f7 v3g7 ] run-decision ;

M: v3f7 decide
    ! decision_test(choose_encoding(get_header_val("accept-encoding")),
    !              none, 406, v3g7);
    ?trace v3g7 decide ;

M: v3g7 decide
    [ drop variances [ "," join "Vary" set-response-header ] when* ]
    [ [ resource-exists? v3g8 v3h7 ] run-decision ] 2bi ;

M: v3g8 decide
    [ drop "if-match" request-header v3g9 v3h10 ] run-decision ;

M: v3g9 decide
    [ drop "if-match" request-header "*" = v3h10 v3g11 ] run-decision ;

M: v3g11 decide
    ?trace [ ] [
        generate-etag
        "if-match" request-header =
        [ v3h10 decide ] [ 412 decide ] if
    ] bi ;

M: v3h7 decide
    [ drop "if-match" request-header "*" = 412 v3i7 ] run-decision ;

M: v3h10 decide
    ! decision_test(get_header_val("if-unmodified-since"),undefined,v3i12,v3h11);
    [ drop "if-unmodified-since" request-header v3h11 v3i12 ] run-decision ;

M: v3h11 decide
    ?trace "if-unmodified-since" request-header 
    [ rfc822>timestamp drop v3h12 decide ] 
    [ 2drop v3i12 decide ] recover ;

M: v3h12 decide
    ?trace dup
    last-modified [ 
        "if-unmodified-since" request-header rfc822>timestamp
        <=> +lt+ = [ 412 decide ] [ v3i12 decide ] if
    ] [ drop ] if* ;

M: v3i4 decide
    ?trace dup moved-permanently? 
    [ "Location" set-response-header 301 decide ] 
    [ v3p3 decide ] if* ;

M: v3i7 decide
    [ drop request method>> "PUT" = v3i4 v3k7 ] run-decision ;

M: v3i12 decide
    [ drop "if-none-match" request-header v3i13 v3l13 ] run-decision ;
    
M: v3i13 decide
    [ drop "if-none-match" request-header "*" = v3j18 v3k13 ] run-decision ;
    
M: v3j18 decide
    [ drop request method>> { "GET" "HEAD" } member? 304 412 ] run-decision ;

M: v3k5 decide
    ?trace dup moved-permanently?
    [ "Location" set-response-header 301 decide ]
    [ v3l5 decide ] if* ;

M: v3k7 decide
    [ previously-existed? v3k5 v3l7 ] run-decision ;

M: v3k13 decide
    ?trace dup generate-etag
    "if-none-match" request-header unquote-header =
    [ v3j18 decide ] [ v3l13 decide ] if ;

M: v3l5 decide
    ?trace dup moved-temporarily? 
    [ "Location" set-response-header 307 decide ] 
    [ v3m5 decide ] if* ;

M: v3l7 decide
    [ drop request method>> "POST" = v3m7 404 ] run-decision ;

M: v3l13 decide
    [ drop "if-modified-since" request-header v3l14 v3m16 ] run-decision ;

M: v3l14 decide
    ?trace "if-modified-since" request-header 
    [ rfc822>timestamp drop v3l15 decide ] 
    [ 2drop v3m16 decide ] recover ;

M: v3l15 decide
    ?trace "if-modified-since" request-header 
    rfc822>timestamp now <=> +gt+ = 
    [ v3m16 decide ] [ v3l17 decide ] if ;

M: v3l17 decide
    ?trace "if-modified-since" request-header rfc822>timestamp
    over last-modified 
    [ nip not ] [ <=> +lt+ = ] 2bi or [ v3m16 decide ] [ 304 decide ] if ;

M: v3m5 decide
    [ drop request method>> "POST" = v3n5 410 ] run-decision ;

M: v3m7 decide
    [ allow-missing-post? v3n11 404 ] run-decision ;

M: v3m16 decide
    [ drop request method>> "DELETE" = v3m20 v3n16 ] run-decision ;

M: v3m20 decide
    [ delete-resource v3m20b 500 ] run-decision ;

M: v3m20b decide
    [ delete-completed? v3o20 202 ] run-decision ;

M: v3n5 decide
    [ allow-missing-post? v3n11 410 ] run-decision ;

: handle-post-result ( resource ? -- )
    [
        do-redirect? 
        [
            "Location" response-header 
            [ 303 decide ] [ 500 decide ] if 
        ] [ v3p11 decide ] if
    ] [ 500 decide ] if ;

M:: v3n11 decide ( resource d -- )
    d ?trace
    ?expect resource post-is-create? [
        resource create-path [
            dup string? [
                drop resource t handle-post-result ! set new path and call content handler
            ] [ drop resource 500 decide ] if
        ] [ resource 500 decide ] if*
    ] [
        resource dup process-post handle-post-result
    ] if ;

M: v3n16 decide
    [ drop request method>> "POST" = v3n11 v3o16 ] run-decision ;

M: v3o14 decide 
    ?trace dup is-conflict? [ 409 decide ] [
        ! call content handler accept_helper()
        v3p11 decide
    ] if ;

M: v3o16 decide
    [ drop request method>> "PUT" = v3o14 v3o18 ] run-decision ;

: get-or-head? ( -- ? )
    request method>> { [ "GET" = ] [ "HEAD" = ] } 1|| ;

: set-etag ( resource -- )
    generate-etag dup =undefined= = not [ "ETag" set-response-header ] [ drop ] if ;

: set-last-modified ( resource -- )
    last-modified dup =undefined= = not
    [ timestamp>http-string "Last-Modified" set-response-header ]
    [ drop ] if ;

: set-expires ( resource -- )
    expires dup =undefined= = not
    [ timestamp>http-string "Expires" set-response-header ]
    [ drop ] if ;

M: v3o18 decide
    ?trace get-or-head? [
        {
            [ set-etag ]
            [ set-last-modified ]
            [ set-expires ]
            [
                [ response accept-content-type tx-metadata ] dip
                [ drop >>content-type ]
                [ (content-types-provided) at [ call( -- content ) >>body ] when* ] 3bi
                2drop
            ]
            [ response code>> [ decide ] [ v3o18b decide ] if* ]
        } cleave
    ] [ v3o18b decide ] if ;

M: v3o18b decide
    [ multiple-choices? 300 200 ] run-decision ;

: has-response-body? ( resource -- ? )
    drop response body>> ;

M: v3o20 decide
    [ has-response-body? v3o18 204 ] run-decision ;

M: v3p3 decide
    [ is-conflict? 409 v3p11 ] run-decision ; ! accept_helper() check result

M: v3p11 decide
    ?expect
    request method>> "PUT" = [ over process-put ] [ t ] if
    [ [ drop "Location" response-header 201 v3o20 ] run-decision ]
    [ ?trace 500 decide ] if ;

PRIVATE>
