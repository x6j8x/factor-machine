USING: accessors alien byte-arrays destructors fry grouping io
io.buffers io.encodings kernel math math.parser namespaces io.pools
sequences specialized-arrays.instances.alien.c-types.uchar ;
IN: http.machine.stream

<PRIVATE

TUPLE: chunked-stream-pool < pool ;

TUPLE: chunked-output-stream stream { chunksize integer } { buffer buffer } ;

M: chunked-stream-pool make-connection
    drop chunked-output-stream new
    32768 [ >>chunksize ] [ <buffer> >>buffer ] bi ;

: <chunked-output-stream> ( stream -- cos )
    [ chunked-stream-pool get acquire-connection ] dip
    >>stream ; inline

DEFER: finish 

PRIVATE>

chunked-stream-pool [ chunked-stream-pool <pool> ] initialize

: make-chunked ( -- )
    output-stream [ 
        dup encoder? 
        [ [ <chunked-output-stream> ] change-stream ] [ <chunked-output-stream> ] if
    ] change ; inline

: end-chunked ( -- )
    output-stream get dup encoder?
    [ [ [ stream>> ] [ finish ] bi ] change-stream drop ] [ finish ] if ;

: with-chunked-output ( quot -- )
    [ make-chunked call( -- ) end-chunked ] with-scope ; inline

<PRIVATE

CONSTANT: CRLF B{ 13 10 }
CONSTANT: LAST-CHUNK B{ 48 13 10 13 10 }

: write-chunk-header ( data stream -- )
    [ length >hex >byte-array CRLF ] dip '[ _ stream-write ] bi@ ; inline

: write-data ( data stream -- )
    [ CRLF ] dip '[ _ stream-write ] bi@ ; inline

: write-chunk ( data stream -- )
    stream>> over length 0 > [
        [ write-chunk-header ] [ write-data ] 2bi
    ] [ 2drop ] if ; inline

: write-available ( cos -- )
    [ buffer>> [ buffer-length ] keep buffer-read ]
    [ ] bi write-chunk ; inline

: write-last-chunk ( cos -- )
    stream>> [ LAST-CHUNK ] dip stream-write ; inline

: write-in-groups ( byte-array stream -- )
    [ binary-object <direct-uchar-array> ] dip
    [ buffer>> size>> <sliced-groups> ]
    [ [ write-chunk ] curry ] bi each ;

: wait-to-write ( len cos -- )
    [ nip ] [ buffer>> buffer-capacity <= ] 2bi
    [ drop ] [ stream-flush ] if ; inline

: reset-stream ( cos -- cos )
    [ buffer>> [ 0 ] dip buffer-reset ] keep
    [ [ stream-flush ] when* f ] change-stream ; inline

: return-to-pool ( cos -- )
    reset-stream chunked-stream-pool get return-connection ; inline

: finish ( cos -- )
    [ write-available ] [ write-last-chunk ] [ return-to-pool ] tri ; inline

PRIVATE>

M: chunked-output-stream dispose*
    [ stream>> [ dispose* ] when* ]
    [ buffer>> dispose* ] bi ;

M: chunked-output-stream stream-element-type drop +byte+ ;

M: chunked-output-stream stream-flush
    [ write-available ]
    [ stream>> stream-flush ] bi ;

M: chunked-output-stream stream-write ( data stream -- )
    2dup [ byte-length ] [ buffer>> size>> ] bi* >
    [ write-in-groups ] [
        [ [ byte-length ] dip wait-to-write ]
        [ buffer>> >buffer ] 2bi
    ] if ;

M: chunked-output-stream stream-write1 ( elt stream -- )
    1 over wait-to-write buffer>> byte>buffer ;
