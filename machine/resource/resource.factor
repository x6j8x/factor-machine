USING: kernel ;

IN: http.machine.resource

GENERIC: init ( resource-def -- resource )

M: object init clone ;

GENERIC: resource-exists? ( resource -- ? )
    ! true X true | false Returning non-true values will result in 404 Not Found.

M: object resource-exists? drop t ;

GENERIC: service-available? ( resource -- ? )
    ! true X true | false 

M: object service-available? drop t ;

GENERIC: is-authorized? ( resource -- t/auth-head ) 
    ! true X true | AuthHead If this returns anything other than true, the response will be 401 Unauthorized. 
    ! The AuthHead return value will be used as the value in the WWW-Authenticate header.

M: object is-authorized? drop t ;

GENERIC: forbidden? ( resource -- ? )
    ! false X true | false

M: object forbidden? drop f ;

GENERIC: allow-missing-post? ( resource -- ? )
    ! false X true | false If the resource accepts POST requests to nonexistent resources, then this should return true.

M: object allow-missing-post? drop f ;

GENERIC: malformed-request? ( resource -- ? )
    ! false X true | false

M: object malformed-request? drop f ;

GENERIC: uri-too-long? ( resource -- ? )
    ! false X true | false

M: object uri-too-long? drop f ;

GENERIC: known-content-type? ( resource -- ? )
    ! true X true | false

M: object known-content-type? drop t ;

GENERIC: valid-content-headers? ( resource -- ? )
    ! true X true | false

M: object valid-content-headers? drop t ;

GENERIC: valid-entity-length? ( resource -- ? )
    ! true X true | false

M: object valid-entity-length? drop t ;

GENERIC: options ( resource -- assoc )
    ! []  [Header] If the OPTIONS method is supported and is used, the return value of this function 
    ! is expected to be a list of pairs representing header names and values that should appear in the response.

M: object options drop { } ;

GENERIC: allowed-methods ( resource -- seq )
    ! ['GET', 'HEAD']  [Method] If a Method not in this list is requested, then a 405 Method Not Allowed 
    ! will be sent. Note that these are all-caps and are atoms. (single-quoted)

M: object allowed-methods drop { "HEAD" "GET" "POST" "PUT" "DELETE" "OPTIONS" } ;

GENERIC: known-methods ( resource -- seq )

M: object known-methods drop { "GET" "HEAD" "POST" "PUT" "DELETE" "TRACE" "CONNECT" "OPTIONS" } ;

GENERIC: delete-resource ( resource -- ? )
    ! false X true | false This is called when a DELETE request should be enacted, and should 
    ! return true if the deletion succeeded.

M: object delete-resource drop f ;

GENERIC: delete-completed? ( resource -- ? )
    ! true X true | false This is only called after a successful delete-resource call, 
    ! and should return false if the deletion was accepted but cannot yet be guaranteed to have finished.

M: object delete-completed? drop t ;

GENERIC: post-is-create? ( resource -- ? )
    ! false  true | false If POST requests should be treated as a request to put content into 
    ! a (potentially new) resource as opposed to being a generic submission for processing, then 
    ! this function should return true. If it does return true, then create-path will be called 
    ! and the rest of the request will be treated much like a PUT to the Path entry returned by that call.

M: object post-is-create? drop f ;

GENERIC: create-path ( resource -- path )
    ! undefined  Path This will be called on a POST request if post-is-create returns true. 
    ! It is an error for this function to not produce a Path if post-is-create returns true. 
    ! The Path returned should be a valid URI part following the dispatcher prefix. 
    ! That Path will replace the previous one in the return value of wrq:disp-path(ReqData) 
    ! for all subsequent resource function calls in the course of this request.

M: object create-path drop f ;

GENERIC: process-post ( resource -- ? )
    ! false X true | false If post-is-create returns false, then this will be 
    ! called to process any POST requests. If it succeeds, it should return true.

M: object process-post drop f ;

GENERIC: content-types-provided ( resource -- assoc )
    ! [{"text/html", to-html}]   [{Mediatype, Handler}] This should return a list of pairs where each pair 
    ! is of the form {Mediatype, Handler} where Mediatype is a string of content-type format and the Handler 
    ! is an atom naming the function which can provide a resource representation in that media type. Content 
    ! negotiation is driven by this return value. For example, if a client request includes an Accept header 
    ! with a value that does not appear as a first element in any of the return tuples, then a 406 Not Acceptable will be sent.

M: object content-types-provided drop { } ;

GENERIC: language-available? ( resource -- ? )

M: object language-available? drop t ;

GENERIC: content-types-accepted  ( resource -- assoc )
    ! []   [{Mediatype, Handler}] This is used similarly to content-types-provided, except that it is for 
    ! incoming resource representations -- for example, PUT requests. Handler functions usually want to use 
    ! wrq:req-body(ReqData) to access the incoming request body.

M: object content-types-accepted drop { } ;

GENERIC: charsets-provided ( resource -- assoc )
    ! no-charset  no-charset | [{Charset, CharsetConverter}] If this is anything other than the atom no-charset,
    ! it must be a list of pairs where each pair is of the form Charset, Converter where Charset is a string naming
    ! a charset and Converter is a callable function in the resource which will be called on the produced body in a GET
    ! and ensure that it is in Charset.

M: object charsets-provided drop { } ;

GENERIC: encodings-provided ( resource -- assoc )
    ! [{"identity", fun(X) -> X end}]   [{Encoding, Encoder}] This must be a list of pairs where in each 
    ! pair Encoding is a string naming a valid content encoding and Encoder is a callable function in the 
    ! resource which will be called on the produced body in a GET and ensure that it is so encoded. 
    ! One useful setting is to have the function check on method, and on GET requests return 
    ! [{"identity", fun(X) -> X end}, {"gzip", fun(X) -> zlib:gzip(X) end}] as this is all that is needed to 
    ! support gzip content encoding.

M: object encodings-provided drop { { "identity" [  ] } } ;

GENERIC: variances ( resource -- seq )
    ! []   [HeaderName] If this function is implemented, it should return a list of strings with header 
    ! names that should be included in a given response's Vary header. The standard conneg headers 
    ! (Accept, Accept-Encoding, Accept-Charset, Accept-Language) do not need to be specified here as 
    ! Webmachine will add the correct elements of those automatically depending on resource behavior.

M: object variances drop f ;

GENERIC: is-conflict? ( resource -- ? )
    ! false  true | false If this returns true, the client will receive a 409 Conflict.

M: object is-conflict? drop f ;

GENERIC: multiple-choices? ( resource -- ? )
    ! false X true | false If this returns true, then it is assumed that multiple representations 
    ! of the response are possible and a single one cannot be automatically chosen, 
    ! so a 300 Multiple Choices will be sent instead of a 200.

M: object multiple-choices? drop f ;

GENERIC: previously-existed? ( resource -- ? )
    ! false X true | false 

M: object previously-existed? drop f ;

GENERIC: moved-permanently? ( resource -- f/uri )
    ! false X  {true, MovedURI} | false

M: object moved-permanently? drop f ;

GENERIC: moved-temporarily? ( resource -- ? )
    ! false X  {true, MovedURI} | false 

M: object moved-temporarily? drop f ;

GENERIC: last-modified ( resource -- f/date )
    ! undefined  undefined | {{YYYY,MM,DD},{Hour,Min,Sec}} 

M: object last-modified drop f ;

GENERIC: expires ( resource -- f/date )
    ! undefined  undefined | {{YYYY,MM,DD},{Hour,Min,Sec}} 

M: object expires drop f ;

GENERIC: generate-etag ( resource -- f/etag )
    ! undefined  undefined | ETag If this returns a value, it will be used as the value of the ETag header 
    ! and for comparison in conditional requests.

M: object generate-etag drop f ;

GENERIC: finish-request ( resource -- ? )
    ! This function, if exported, is called just before the final response is constructed and sent. The Result is ignored,
    ! so any effect of this function must be by returning a modified ReqData .

M: object finish-request drop t ;

GENERIC: keep-alive? ( resource -- ? )

M: object keep-alive? drop t ;