USING: accessors arrays assocs combinators.short-circuit fry
io.encodings.iana kernel math.order math.parser mime.types peg
sequences sorting splitting ;
IN: http.machine.mime

<PRIVATE

: find-q-param ( seq -- q-val/1 )
    dup empty? [ drop 1 ] [
        unclip-slice "=" split unclip-slice "q" = 
        [ nip first [ string>number [ 0 ] unless* ] [ 0 ] if* ]
        [ drop find-q-param ] if
    ] if ; inline recursive

: prioritize ( param -- mt prio )
    ";" split dup length 1 =
    [ first 1 ]
    [ unclip-slice swap find-q-param ] if ; inline recursive

: build-accept-list ( accept -- seq )
    [ V{ } clone ] dip "," split
    [ prioritize swap 2array over push ] each
    [ [ first ] bi@ swap <=> ] sort values ;

: match-major-type ( str cp -- mt/f )
    swap "/" split first
    '[ first "/" split first _ = ] find nip first ; inline

: mt-exact-match? ( mt cp -- mt/f )
    dupd key? [  ] [ drop f ] if ; inline

: mt-any-match? ( mt cp -- mt/f )
    over "*/*" = [ nip first first ] [ 2drop f ] if ; inline

: mt-major-match? ( mt cp -- mt/f )
    over last 42 = [ match-major-type ] [ 2drop f ] if ; inline

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