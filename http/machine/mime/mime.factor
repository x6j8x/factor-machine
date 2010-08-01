USING: accessors arrays ascii assocs combinators.short-circuit
fry io.encodings.iana kernel make math math.order math.parser
mime.types peg sequences sequences.deep sorting splitting
strings ;
IN: http.machine.mime

TUPLE: media-type major minor q formatted ;

: <media-type> ( major minor q -- media-type )
    2over "/" glue media-type boa ;

<PRIVATE


! Accept         = "Accept" ":" #( media-range [ accept-params ] )
! media-range    = ( "*/*"
!                  | ( type "/" "*" )
!                  | ( type "/" subtype ) ) *( ";" parameter )
! accept-params  = ";" "q" "=" qvalue *( accept-extension )
! accept-extension = ";" token [ "=" ( token | quoted-string ) ]

: 'space' ( -- parser )
    [ " \t" member? ] satisfy repeat0 hide ;

: 'comma' ( -- parser )
    "," token hide ;

: 'type' ( -- parser )
    [ { [ letter? ] [ CHAR: + = ] [ CHAR: - = ] [ CHAR: . = ] } 1|| ] satisfy repeat1
    "*" token 2choice [ >string ] action ;

: 'float-value' ( -- parser )
    [
        "0" token optional ,
        "." token ,
        [ digit? ] satisfy repeat1 [ >string ] action ,
    ] seq* [ flatten concat string>number ] action ;

: 'q-param' ( -- parser )
    [
        "q" token hide ,
        "=" token hide ,
        'float-value' ,
    ] seq* ;

: 'accept-params' ( -- parser )
    [
        'space' ,
        ";" token hide ,
        'space' ,
        'q-param' ,
    ] seq* [ flatten first ] action ;

: 'media-range' ( -- parser )
    [
        'comma' optional ,
        'space' ,
        'type' ,
        "/" token hide ,
        'type' ,
        'space' ,
        'accept-params' optional ,
        'space' ,
    ] seq* [ 
        flatten dup length 3 =
        [ first3 <media-type> ] [ first2 1 <media-type> ] if 
    ] action ;

PEG: parse-accept-spec ( str -- types )
    [
        'space' ,
        'media-range' repeat1 ,
    ] seq* [ flatten ] action ;


: build-accept-list ( accept -- seq )
    parse-accept-spec [ [ q>> ] bi@ swap <=> ] sort ;

: match-major-type ( str cp -- mt/f )
    swap major>>
    '[ first "/" split first _ = ] find nip first ; inline

: mt-exact-match? ( mt cp -- mt/f )
    [ dup formatted>> ] dip
    key? [ formatted>> ] [ drop f ] if ; inline

: mt-any-match? ( mt cp -- mt/f )
    over formatted>> "*/*" = [ nip first first ] [ 2drop f ] if ; inline

: mt-major-match? ( mt cp -- mt/f )
    over minor>> "*" = [ match-major-type ] [ 2drop f ] if ; inline

DEFER: find-media-type

: mt-decide-match ( rest hd cp match? -- mt/f )
    [ [ 3drop ] dip ] [ nip find-media-type ] if* ; inline

: find-media-type ( seq cp -- mt )
    over empty? [ 2drop f ] [
        [ unclip ] dip 2dup ! rest hd cp hd cp
        {
            [ mt-exact-match? ]
            [ mt-any-match? ]
            [ mt-major-match? ]
        } 2|| mt-decide-match
    ] if ; inline recursive

PRIVATE>

: choose-media-type ( accept cp -- mt )
    [ build-accept-list ] dip find-media-type ; inline

: choose-charset ( responder accept -- charset )
    2drop "utf8" ; inline

: choose-encoding ( responder encoding -- encoding )
    nip ;

: build-content-type ( response -- content-type )
    [ content-type>> ] [ content-charset>> ] bi
    over mime-type-encoding encoding>name or
    [ "application/octet-stream" or ] dip
    [ "; charset=" glue ] when* ;