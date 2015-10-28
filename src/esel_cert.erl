%%%-------------------------------------------------------------------
%%% @author Heinz Nikolaus Gies <heinz@licenser.net>
%%% @copyright (C) 2015, Heinz Nikolaus Gies
%%% @doc
%%%
%%% @end
%%% Created : 28 Oct 2015 by Heinz Nikolaus Gies <heinz@licenser.net>
%%%-------------------------------------------------------------------
-module(esel_cert).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([cn/1, fingerprint/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------


cn(<<"---", _/binary>> = Cert) ->
    [PemData] = public_key:pem_decode(Cert),
    cn(PemData);
cn({'Certificate', Cert1, not_encrypted}) ->
    cn(Cert1);
cn(Cert) ->
    OTPCertificate = public_key:pkix_decode_cert(Cert, otp),
    OTPTBSCertificate = OTPCertificate#'OTPCertificate'.tbsCertificate,
    case OTPTBSCertificate#'OTPTBSCertificate'.subject of
        {rdnSequence,[Attrs | _]} ->
            [Val] = [ V ||
                        #'AttributeTypeAndValue'{
                           type = {2,5,4,3}, value = {printableString, V}} <- Attrs],
            Val;
        {rdnSequence,[]} ->
            undefined
    end.

fingerprint(<<"---", _/binary>> = Cert) ->
    [PemData] = public_key:pem_decode(Cert),
    fingerprint(PemData);
fingerprint(PemData) ->
    Pub = public_key:pem_entry_decode(PemData),
    crypto:hash(sha, public_key:der_encode('Certificate', Pub)).

%%%===================================================================
%%% Internal functions
%%%===================================================================
