USING: kernel ;
IN: http.machine.util

: choose-media-type ( accept seq -- mt )
    2drop "text/html" ; inline

: choose-charset ( responder accept -- charset )
    2drop "utf8" ; inline

: choose-encoding ( responder encoding -- encoding )
    nip ;

: unquote-header ( value -- unquoted )
    ;