USING: accessors arrays assocs calendar calendar.format
combinators combinators.short-circuit continuations formatting
fry hashtables http.machine.data http.machine.mime
http.machine.resource http.machine.states http.machine.util
kernel locals math math.order memoize namespaces sequences
strings ; inline
IN: http.machine.flow

GENERIC: decide ( resource d -- )

<PRIVATE

: decision-test ( resource ? true false -- )
    pick [ drop ] [ nip ] if nip decide ; inline

: run-decision ( resource state quot -- )
    [ drop ] dip [  ] swap 
    [ decision-test ] compose bi ; inline

M: integer decide nip [ response ] dip >>code drop ; inline

M: v3b13 decide
    [ service-available? v3b12 503 ] run-decision ; inline

M: v3b12 decide
    [ [ request method>> ] dip known-methods member? v3b11 501 ] run-decision ; inline

M: v3b11 decide
    [ uri-too-long? 414 v3b10 ] run-decision ; inline

M: v3b10 decide ( resource d -- )
    drop dup [ request method>> ] dip allowed-methods
    [ nip ] [ member? ] 2bi
    [ drop v3b9 decide ]
    [
        nip "," join "Allow" set-response-header
        response 405 >>code drop
    ] if ; inline

M: v3b9 decide
    [ malformed-request? 400 v3b8 ] run-decision ; inline

M: v3b8 decide
    drop [  ] [ is-authorized? ] bi
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
    } cond ; inline

M: v3b7 decide
    [ forbidden? 403 v3b6 ] run-decision ; inline

M: v3b6 decide
    [ valid-content-headers? v3b5 501 ] run-decision ; inline

M: v3b5 decide
    [ known-content-type? v3b4 415 ] run-decision ; inline

M: v3b4 decide
    [ valid-entity-length? v3b3 413 ] run-decision ; inline

M: v3b3 decide
    drop request method>> "OPTIONS" = 
    [        
        options [ [ second ] [ first ] bi set-response-header ] each
    ] [ v3c3 decide ] if ; inline

: (content-types-provided) ( resource -- ct )
    content-types-provided >alist ; inline

: ?content-types-provided ( resource quot -- )
    [
        dup (content-types-provided) dup empty? 
        [ drop 503 decide ]
    ] dip if ; inline

M: v3c3 decide
    drop "accept" get-request-header
    [ v3c4 decide ] [
        [ [ nip first first "accept-content-type" set-tx-metadata ] ?content-types-provided ]
        [ v3d4 decide ] bi
    ] if ; inline

M: v3c4 decide
    drop "accept" get-request-header 
    '[ _ swap choose-media-type
        [ "accept-content-type" set-tx-metadata v3d4 decide ]
        [ 406 decide ] if*
    ] ?content-types-provided ; inline

M: v3d4 decide
    [ drop "accept-language" get-request-header v3d5 v3e5 ] run-decision ; inline

M: v3d5 decide
    [ language-available? v3e5 406 ] run-decision ; inline

M: v3e5 decide
    drop "accept-charset" get-request-header
    [ v3e6 decide ]
    [
        [ "*" choose-charset "accept-content-charset" set-tx-metadata ]
        [ v3f6 decide ] bi 
    ] if ; inline

M: v3e6 decide
    drop [  ] [ 
        "accept-charset" get-request-header choose-charset 
        [ "accept-content-charset" set-tx-metadata ] keep
        [ v3f6 decide ] [ 406 decide ] if
    ] bi ; inline

M: v3f6 decide
    drop "accept-encoding" get-request-header
    [ v3f7 decide ] [ v3g7 decide ] if ; inline

M: v3f7 decide
    ! decision_test(choose_encoding(get_header_val("accept-encoding")),
    !              none, 406, v3g7); inline
    drop v3g7 decide ; inline

M: v3g7 decide
    [ drop variances [ "," join "Vary" set-response-header ] when* ]
    [ [ resource-exists? v3g8 v3h7 ] run-decision ] 2bi ; inline

M: v3g8 decide
    drop "if-match" get-request-header
    [ v3g9 decide ] [ v3h10 decide ] if ; inline

M: v3g9 decide
    drop "if-match" get-request-header "*" =
    [ v3h10 decide ] [ v3g11 decide ] if ; inline

M: v3g11 decide
    drop [ ] [
        generate-etag
        "if-match" get-request-header =
        [ v3h10 decide ] [ 412 decide ] if
    ] bi ; inline

M: v3h7 decide
    drop "if-match" get-request-header "*" =
    [ 412 decide ] [ v3i7 decide ] if ; inline

M: v3h10 decide
    ! decision_test(get_header_val("if-unmodified-since"),undefined,v3i12,v3h11); inline
    drop "if-unmodified-since" get-request-header 
    [ v3h11 decide ] [ v3i12 decide ] if ; inline

M: v3h11 decide
    drop "if-unmodified-since" get-request-header 
    [ rfc822>timestamp drop v3h12 decide ] 
    [ 2drop v3i12 decide ] recover ; inline

M: v3h12 decide
    drop dup
    last-modified [ 
        "if-unmodified-since" get-request-header rfc822>timestamp
        <=> +lt+ = [ 412 decide ] [ v3i12 decide ] if
    ] [ drop ] if* ; inline

M: v3i4 decide
    drop dup moved-permanently? 
    [ "Location" set-response-header 301 decide ] 
    [ v3p3 decide ] if* ; inline

M: v3i7 decide
    [ drop request method>> "PUT" = v3i4 v3k7 ] run-decision ; inline

M: v3i12 decide
    [ drop "if-none-match" get-request-header v3l13 v3i13 ] run-decision ; inline
    
M: v3i13 decide
    [ drop "if-none-match" get-request-header "*" = v3j18 v3k13 ] run-decision ; inline
    
M: v3j18 decide
    [ drop request method>> { "GET" "HEAD" } member? 304 412 ] run-decision ; inline

M: v3k5 decide
    drop dup moved-permanently?
    [ "Location" set-response-header 301 decide ]
    [ v3l5 decide ] if* ; inline

M: v3k7 decide
    [ previously-existed? v3k5 v3l7 ] run-decision ; inline

M: v3k13 decide
    drop dup generate-etag
    "if-non-match" get-request-header unquote-header =
    [ v3j18 decide ] [ v3l13 decide ] if ; inline

M: v3l5 decide
    drop dup moved-temporarily? 
    [ "Location" set-response-header 307 decide ] 
    [ v3m5 decide ] if* ; inline

M: v3l7 decide
    [ drop request method>> "POST" = v3m7 404 ] run-decision ; inline

M: v3l13 decide
    [ drop "if-modified-since" get-request-header v3l14 v3m16 ] run-decision ; inline

M: v3l14 decide
    drop "if-modified-since" get-request-header 
    [ rfc822>timestamp drop v3l15 decide ] 
    [ 2drop v3m16 decide ] recover ; inline

M: v3l15 decide
    drop "if-modified-since" get-request-header 
    rfc822>timestamp now <=> +gt+ = 
    [ v3m16 decide ] [ v3l17 decide ] if ; inline

M: v3l17 decide
    drop "if-modified-since" get-request-header rfc822>timestamp
    over last-modified 
    [ nip not ] [ <=> +lt+ = ] 2bi or [ v3m16 decide ] [ 304 decide ] if ; inline

M: v3m5 decide
    [ drop request method>> "POST" = v3n5 410 ] run-decision ; inline

M: v3m7 decide
    [ allow-missing-post? v3n11 404 ] run-decision ; inline

M: v3m16 decide
    [ drop request method>> "DELETE" = v3m20 v3n16 ] run-decision ; inline

M: v3m20 decide
    [ delete-resource v3m20b 500 ] run-decision ; inline

M: v3m20b decide
    [ delete-completed? v3o20 202 ] run-decision ; inline

M: v3n5 decide
    [ allow-missing-post? v3n11 410 ] run-decision ; inline

: handle-post-result ( resource ? -- )
    [
        do-redirect? 
        [
            "Location" get-response-header 
            [ 303 decide ] [ 500 decide ] if 
        ] [ v3p11 decide ] if
    ] [ 500 decide ] if ; inline

M:: v3n11 decide ( resource d -- )
    resource post-is-create? [
        resource create-path [
            dup string? [
                drop resource t handle-post-result ! set new path and call content handler
            ] [ drop resource 500 decide ] if
        ] [ resource 500 decide ] if*
    ] [
        resource dup process-post handle-post-result
    ] if ; inline

M: v3n16 decide
    [ drop request method>> "POST" = v3n11 v3o16 ] run-decision ; inline

M: v3o14 decide 
    drop dup is-conflict? [ 409 decide ] [
        ! call content handler accept_helper()
        v3p11 decide
    ] if ; inline

M: v3o16 decide
    [ drop request method>> "PUT" = v3o14 v3o18 ] run-decision ; inline

: get-or-head? ( -- ? )
    request method>> { [ "GET" = ] [ "HEAD" = ] } 1|| ; inline

: set-etag ( resource -- )
    generate-etag dup =undefined= = not [ "ETag" set-response-header ] [ drop ] if ; inline

: set-last-modified ( resource -- )
    last-modified dup =undefined= = not
    [ timestamp>http-string "Last-Modified" set-response-header ]
    [ drop ] if ; inline

: set-expires ( resource -- )
    expires dup =undefined= = not
    [ timestamp>http-string "Expires" set-response-header ]
    [ drop ] if ; inline

M: v3o18 decide
    drop get-or-head? [
        {
            [ set-etag ]
            [ set-last-modified ]
            [ set-expires ]
            [
                [ response "accept-content-type" tx-metadata ] dip
                [ (content-types-provided) at call( -- content ) >>body ]
                [ drop >>content-type ] 3bi 2drop
                ! get content quot call content-types-provided
                ! call content quot and set response body
            ]
            [ v3o18b decide ]
        } cleave
    ] [ v3o18b decide ] if ; inline

M: v3o18b decide
    [ multiple-choices? 300 200 ] run-decision ; inline

: has-response-body? ( resource -- ? )
    drop response body>> ; inline

M: v3o20 decide
    [ has-response-body? v3o18 204 ] run-decision ; inline

M: v3p3 decide
    [ is-conflict? 409 v3p11 ] run-decision ; inline ! accept_helper() check result

M: v3p11 decide
    [ drop "Location" get-response-header v3o20 201 ] run-decision ; inline

PRIVATE>
